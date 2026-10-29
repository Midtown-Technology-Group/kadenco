// SPDX-License-Identifier: AGPL-3.0-or-later
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../src/store.mjs';
import {Bridge} from '../src/bridge.mjs';
import {httpServer} from '../src/server.mjs';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';

function fixture(t){
  const store=new Store(':memory:',randomBytes(32));t.after(()=>store.close());
  let now=Date.now(),requests=[],outage=false,allowed=true,projectAllowed=true;
  const policy={principals:[{id:'eddie',sessions:['pilot']}],sessions:[{id:'pilot',host:'remote',threadId:'t',observeAfter:'2026-10-20T00:00:00Z'}],callbackHosts:['callbacks.example.com']};
  const data={thread:{threadId:'t',projectId:'p',activeRunId:'r',pendingRequestCount:1},recentRuns:[],items:[]},posts=[],calls=[];
  const bridge=new Bridge({store,policy:()=>policy,backend:{read:async()=>structuredClone(data)},now:()=>now,
    post:async(_u,_h,body)=>{const event=JSON.parse(body);posts.push(event);return {status:200,body:JSON.stringify({challenge:event.challenge})};}});
  bridge.commands={grant:(_owner,_host,project)=>{if(!allowed||project&&!projectAllowed)throw Object.assign(new Error('forbidden'),{reason:'forbidden'});},
    requests:async(owner,p,options)=>{calls.push({owner,p,options});if(outage)throw new Error('source_unavailable');
      const page=requests.filter(r=>!p.after_request_id||r.native_request_id>p.after_request_id);return {project_id:'p',requests:page.slice(0,25),next_cursor:page.length>25?page[24].native_request_id:null};}};
  bridge.fleetReads={read:async()=>({...structuredClone(data),runs:structuredClone(data.recentRuns)})};
  const p={name:'t3.thread.activity',arguments:{host:'remote',thread_id:'t'},delivery:{mode:'webhook',url:'https://callbacks.example.com/event',secret:'whsec_'+randomBytes(32).toString('base64')}};
  return {store,policy,data,posts,calls,bridge,p,requests:v=>requests=v,outage:v=>outage=v,allowed:v=>allowed=v,projectAllowed:v=>projectAllowed=v,advance:ms=>now+=ms};
}

test('subscription atomically owns its return lane; refresh persists identity, unsubscribe/expiry remove access',async t=>{
  const f=fixture(t),policy=JSON.stringify(f.policy);
  assert.equal(f.bridge.lanes.get('eddie',f.p.arguments).state,'inactive');
  const a=await f.bridge.subscribe('eddie',f.p),lane=f.bridge.lanes.get('eddie',f.p.arguments);
  assert.equal(lane.state,'active');assert.equal(lane.mechanism,'native_user_input');
  assert.equal((await f.bridge.subscribe('eddie',f.p)).id,a.id);
  assert.equal(f.bridge.lanes.get('eddie',f.p.arguments).lane_id,lane.lane_id);
  assert.equal(f.store.all('subscription').length,1);assert.equal(JSON.stringify(f.policy),policy);
  assert.equal(f.store.all('command').length,0);assert.equal(f.store.all('exchange').length,0);
  f.bridge.unsubscribe('eddie',f.p);assert.equal(f.bridge.lanes.get('eddie',f.p.arguments).state,'inactive');
  await f.bridge.subscribe('eddie',f.p);f.advance(86400001);assert.equal(f.bridge.lanes.get('eddie',f.p.arguments).state,'inactive');
});
test('temporary event lease survives refresh/restart without extending grants or its first deadline',async t=>{
  const f=fixture(t),policy=JSON.stringify(f.policy),p={...f.p,arguments:{...f.p.arguments,lease_seconds:3600}};
  const first=await f.bridge.subscribe('eddie',p),deadline=first.refreshBefore;
  assert.equal(Date.parse(deadline)-f.store.all('subscription')[0].refreshedAt,3600000);
  f.advance(60000);
  const resumed=new Bridge({...f.bridge});resumed.commands=f.bridge.commands;resumed.fleetReads=f.bridge.fleetReads;
  assert.equal((await resumed.subscribe('eddie',f.p)).refreshBefore,deadline);
  assert.equal(resumed.lanes.get('eddie',f.p.arguments).expires_at,deadline);
  assert.equal(JSON.stringify(f.policy),policy);assert.equal(f.store.all('command').length,0);
  f.advance(3600000);assert.equal(resumed.lanes.get('eddie',f.p.arguments).state,'inactive');
  await assert.rejects(resumed.subscribe('eddie',f.p),/subscription_lease_expired/);
});

test('explicit nonexpiring standing lanes survive restart and time, while revocation and temporary leases still stop delivery',async t=>{
  const f=fixture(t),policy=JSON.stringify(f.policy);
  const standing={...f.p,ttlMs:null};
  const first=await f.bridge.subscribe('eddie',standing);assert.equal(first.refreshBefore,null);
  f.advance(3*86400000);
  const resumed=new Bridge({...f.bridge});resumed.commands=f.bridge.commands;resumed.fleetReads=f.bridge.fleetReads;
  assert.equal(resumed.lanes.get('eddie',f.p.arguments).state,'active');
  assert.equal(resumed.lanes.get('eddie',f.p.arguments).expires_at,null);
  assert.equal((await resumed.subscribe('eddie',f.p)).refreshBefore,null);
  f.requests([{native_request_id:'persistent-question',run_id:'r',live_answer_allowed:true}]);f.posts.length=0;
  await resumed.observe();await resumed.deliver();assert.equal(f.posts.length,1);
  assert.equal(JSON.stringify(f.policy),policy);
  const sessionId=resumed.lanes.get('eddie',f.p.arguments).session_id;
  assert.equal((await resumed.read('eddie',sessionId)).thread.threadId,'t');
  f.allowed(false);assert.throws(()=>resumed.lanes.get('eddie',f.p.arguments),/forbidden/);
  await assert.rejects(resumed.read('eddie',sessionId),/forbidden/);
  f.allowed(true);resumed.unsubscribe('eddie',f.p);
  const temporary={...f.p,ttlMs:null,arguments:{...f.p.arguments,lease_seconds:60},delivery:{...f.p.delivery,url:'https://callbacks.example.com/temporary'}};
  const bounded=await resumed.subscribe('eddie',temporary);assert.ok(bounded.refreshBefore);
  f.advance(60001);assert.equal(resumed.lanes.get('eddie',f.p.arguments).state,'inactive');
  await assert.rejects(resumed.subscribe('eddie',{...temporary,arguments:f.p.arguments}),/subscription_lease_expired/);
});

test('malformed stored lifetime cannot masquerade as an explicitly nonexpiring lane',async t=>{
  const f=fixture(t),r=await f.bridge.subscribe('eddie',{...f.p,ttlMs:null}),valid=f.store.get('subscription',r.id);
  for(const expires of [undefined,0,-1,NaN,Infinity,'99999999999999',null]){
    f.store.put('subscription',r.id,{...valid,expires,nonExpiring:undefined});
    assert.equal(f.bridge.lanes.get('eddie',f.p.arguments).state,'inactive');
    assert.equal(f.bridge.lanes.sessions('eddie').length,0);
  }
  f.store.put('subscription',r.id,valid);assert.equal(f.bridge.lanes.get('eddie',f.p.arguments).state,'active');
});
test('concurrent temporary subscriptions admit only one, preserve standing monitoring, and release admission on unsubscribe',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);
  const temp=path=>({...f.p,arguments:{...f.p.arguments,lease_seconds:60},delivery:{...f.p.delivery,url:'https://callbacks.example.com/'+path}});
  const a=temp('temporary-a'),b=temp('temporary-b'),results=await Promise.allSettled([f.bridge.subscribe('eddie',a),f.bridge.subscribe('eddie',b)]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(results.filter(r=>r.status==='rejected'&&/temporary_lane_limit/.test(r.reason.message)).length,1);
  const active=results[0].status==='fulfilled'?a:b,other=active===a?b:a;
  f.bridge.unsubscribe('eddie',active);assert.ok((await f.bridge.subscribe('eddie',other)).id);
  const standing=f.store.all('subscription').find(s=>s.url===f.p.delivery.url);assert.equal(standing.active,true);assert.equal(standing.leaseExpires,undefined);
});
test('temporary subscription refuses unauthorized targets and invalid duration without stored lanes',async t=>{
  const f=fixture(t);f.allowed(false);
  await assert.rejects(f.bridge.subscribe('eddie',{...f.p,arguments:{...f.p.arguments,lease_seconds:60}}),/forbidden/);
  f.allowed(true);
  for(const lease_seconds of [0,-1,3601,1.5])await assert.rejects(f.bridge.subscribe('eddie',{...f.p,arguments:{...f.p.arguments,lease_seconds}}),/invalid_subscription_lease/);
  assert.equal(f.store.all('subscription').length,0);
});
test('standing subscription cannot be converted into a temporary lease',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);const before=JSON.stringify(f.store.all('subscription'));
  await assert.rejects(f.bridge.subscribe('eddie',{...f.p,arguments:{...f.p.arguments,lease_seconds:3600}}),/standing_subscription_preserved/);
  assert.equal(JSON.stringify(f.store.all('subscription')),before);
});
test('shortened deadline persists through SQLite reopen and same-identity unsubscribe/resubscribe',async t=>{
  const f=fixture(t),dir=mkdtempSync(join(tmpdir(),'eddie-lease-')),path=join(dir,'state.db'),key=randomBytes(32);
  t.after(()=>rmSync(dir,{recursive:true,force:true}));let store=new Store(path,key);
  f.bridge.store=store;
  try{
    const first=await f.bridge.subscribe('eddie',{...f.p,arguments:{...f.p.arguments,lease_seconds:3600}});
    f.advance(1000);const shorter=await f.bridge.subscribe('eddie',{...f.p,arguments:{...f.p.arguments,lease_seconds:60}});
    assert.ok(shorter.refreshBefore<first.refreshBefore);store.close();store=new Store(path,key);
    const resumed=new Bridge({...f.bridge,store});resumed.commands=f.bridge.commands;resumed.fleetReads=f.bridge.fleetReads;
    resumed.unsubscribe('eddie',f.p);assert.equal((await resumed.subscribe('eddie',f.p)).refreshBefore,shorter.refreshBefore);
    f.advance(60001);await assert.rejects(resumed.subscribe('eddie',f.p),/subscription_lease_expired/);
  }finally{store.close();}
});
test('expired temporary lease never delivers its queued native input event',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',{...f.p,arguments:{...f.p.arguments,lease_seconds:60}});f.posts.length=0;
  f.requests([{native_request_id:'question1',run_id:'r',live_answer_allowed:true}]);await f.bridge.observe();assert.equal(f.store.all('delivery').length,1);
  f.advance(60001);await f.bridge.deliver();assert.equal(f.posts.length,0);assert.equal(f.bridge.lanes.get('eddie',f.p.arguments).state,'inactive');assert.equal(f.store.all('command').length,0);
});

test('authorized thread subscription works without pre-enrolled sessions and revokes generated result access',async t=>{
  const f=fixture(t);f.policy.sessions=[];f.policy.principals[0].sessions=[];
  await f.bridge.subscribe('eddie',f.p);const lane=f.bridge.lanes.get('eddie',f.p.arguments);
  assert.deepEqual(f.bridge.sessions('eddie').map(s=>s.id),[lane.session_id]);
  assert.equal((await f.bridge.read('eddie',lane.session_id)).thread.threadId,'t');
  await assert.rejects(f.bridge.read('other',lane.session_id),/forbidden/);
  f.bridge.unsubscribe('eddie',f.p);assert.equal(f.bridge.sessions('eddie').length,0);
  await assert.rejects(f.bridge.read('eddie',lane.session_id),/forbidden/);
});

test('MCP discovery advertises two-way thread subscriptions before any session exists',async t=>{
  const f=fixture(t),token='test-token';f.policy.sessions=[];f.policy.principals[0].sessions=[];
  f.policy.principals[0].tokenSha256=createHash('sha256').update(token).digest('hex');f.policy.principals[0].commandHosts=[{host:'remote'}];
  const server=httpServer(f.bridge);await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
  const client=new Client({name:'test',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});t.after(()=>client.close());
  await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`),{requestInit:{headers:{Authorization:'Bearer '+token}}}));
  assert.ok((await client.listTools()).tools.some(t=>t.name==='get_thread_lane'));
  const result=await client.callTool({name:'get_thread_lane',arguments:f.p.arguments});assert.equal(result.structuredContent.state,'inactive');
  const rpc=async(method,params={})=>(await fetch(`http://127.0.0.1:${server.address().port}/mcp`,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method,accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{name:'test',version:'1'},'io.modelcontextprotocol/clientCapabilities':{}}}})})).json();
  const events=await rpc('events/list');assert.equal(events.result.events[0].name,'t3.thread.activity');
  const fleet=events.result.events.find(e=>e.name==='t3.fleet.activity');assert.ok(fleet);
  assert.deepEqual(fleet.inputSchema.required,['scope']);assert.equal(fleet.inputSchema.properties.scope.const,'authorized_fleet');
  assert.ok((await client.listTools()).tools.some(t=>t.name==='get_fleet_event_status'));
  const inputEvent=events.result.events[0].payloadSchema.oneOf.find(s=>s.properties.kind.const==='input_requested');
  assert.deepEqual(Object.keys(inputEvent.properties).sort(),['host','kind','lane_id','live_answer_allowed','native_request_id','run_id','session_id','thread_id']);
  assert.match(events.result.events[0].description,/reply_contract/);
  assert.deepEqual(events.result.events[0].inputSchema.required,['host','thread_id']);
  assert.equal(events.result.events[0].inputSchema.properties.lease_seconds.maximum,3600);
  assert.equal(events.result.events[0].inputSchema.properties.lease_seconds.minimum,60);
  const standing=await rpc('events/subscribe',{...f.p,ttlMs:null,delivery:{...f.p.delivery,url:'https://callbacks.example.com/standing'}});
  assert.equal(standing.result.refreshBefore,null);
  assert.ok((await rpc('events/subscribe',{...f.p,arguments:{...f.p.arguments,lease_seconds:3600}})).result.id);
  assert.ok((await rpc('events/subscribe',{...f.p,arguments:{...f.p.arguments,lease_seconds:3601}})).error);
  assert.ok((await rpc('events/subscribe',f.p)).result.id);
});

test('questions and completions share one thread subscription, with exact IDs and stable duplicate delivery',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);f.posts.length=0;
  f.requests([{native_request_id:'question1',run_id:'r',live_answer_allowed:true}]);
  await f.bridge.observe();await f.bridge.observe();assert.equal(f.store.all('delivery').length,1);
  await f.bridge.deliver();assert.equal(f.posts[0].name,'t3.thread.activity');
  assert.deepEqual(f.posts[0].data,{session_id:f.bridge.lanes.get('eddie',f.p.arguments).session_id,host:'remote',thread_id:'t',lane_id:f.bridge.lanes.get('eddie',f.p.arguments).lane_id,kind:'input_requested',run_id:'r',native_request_id:'question1',live_answer_allowed:true});
  f.data.thread.activeRunId=null;f.data.thread.pendingRequestCount=0;f.data.recentRuns=[{runId:'r',status:'completed',completedAt:new Date().toISOString()}];
  await f.bridge.observe();await f.bridge.deliver();assert.equal(f.posts[1].data.kind,'task_finished');assert.equal(f.posts[1].data.run_id,'r');
  assert.notEqual(f.posts[0].eventId,f.posts[1].eventId);
  await f.bridge.observe();await f.bridge.deliver();assert.equal(f.posts.length,2);
});

test('pending native question pagination has no silent first-page loss',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);
  f.requests(Array.from({length:31},(_,i)=>({native_request_id:'q'+String(i).padStart(2,'0'),run_id:'r',live_answer_allowed:true})));
  await f.bridge.observe();assert.equal(f.store.all('delivery').length,31);
  assert.ok(f.calls.some(c=>c.p.after_request_id==='q24'));
});

test('revocation, session rebinding and resolved questions refuse delivery; source outage retries',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);f.posts.length=0;
  f.requests([{native_request_id:'q',run_id:'r',live_answer_allowed:true}]);await f.bridge.observe();
  f.outage(true);await f.bridge.deliver();assert.equal(f.store.all('delivery')[0].status,'pending');assert.equal(f.posts.length,0);
  f.outage(false);f.advance(30001);f.requests([]);await f.bridge.deliver();assert.equal(f.store.all('delivery')[0].status,'revoked');
  f.requests([{native_request_id:'q2',run_id:'r',live_answer_allowed:false}]);await f.bridge.observe();
  const sub=f.store.all('subscription')[0];f.store.put('subscription',sub.id,{...sub,threadId:'different'});await f.bridge.deliver();assert.equal(f.posts.length,0);
  f.allowed(false);
  await assert.rejects(f.bridge.subscribe('eddie',f.p),/forbidden/);
  assert.throws(()=>f.bridge.lanes.get('eddie',f.p.arguments),/forbidden/);
});

test('a project grant revoked after completion observation blocks delivery and generated session reads',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);f.posts.length=0;
  const id=f.bridge.lanes.get('eddie',f.p.arguments).session_id;
  f.data.thread.activeRunId=null;f.data.thread.pendingRequestCount=0;f.data.recentRuns=[{runId:'r',status:'completed',completedAt:new Date(Date.now()+1).toISOString()}];
  await f.bridge.observe();f.projectAllowed(false);await f.bridge.deliver();
  assert.equal(f.posts.length,0);assert.equal(f.store.all('delivery')[0].status,'revoked');
  await assert.rejects(f.bridge.read('eddie',id),/forbidden/);
});

test('lane identity and native binding recover from stored subscription without an in-memory enrollment',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);
  const before=f.bridge.lanes.get('eddie',f.p.arguments);
  const restarted=new Bridge({store:f.store,policy:()=>f.policy,backend:f.bridge.backend,post:f.bridge.post,now:f.bridge.now});
  restarted.commands=f.bridge.commands;restarted.fleetReads=f.bridge.fleetReads;
  assert.deepEqual(restarted.lanes.get('eddie',f.p.arguments),before);
  assert.equal((await restarted.read('eddie',before.session_id)).thread.threadId,'t');
  f.data.thread.projectId='different';await assert.rejects(restarted.read('eddie',before.session_id),/identity_mismatch/);
});
