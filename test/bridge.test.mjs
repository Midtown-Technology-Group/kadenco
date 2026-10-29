// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { Webhook } from 'standardwebhooks';
import { Store } from '../src/store.mjs';
import { Bridge, FOLLOWUP } from '../src/bridge.mjs';
import { callbackUrl, publicAddress, postWebhook } from '../src/webhook.mjs';
import { httpServer, principalFor } from '../src/server.mjs';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

function fixture(t) {
  const dir=mkdtempSync(join(tmpdir(),'eddie-t3-')), key=randomBytes(32);
  const store=new Store(join(dir,'bridge.db'),key);
  let now=Date.now(), sends=0, code=204;
  const token='test-bearer-'+randomUUID();
  const policy={callbackHosts:['callbacks.example.com'],principals:[{id:'eddie',sessions:['a'],tokenSha256:createHash('sha256').update(token).digest('hex')}],sessions:[
    {id:'a',host:'test-host',threadId:'thread-a',observeAfter:'2026-10-18T14:00:00Z',followup:{action:'verify_result',dedicated:true,expiresAt:now+86400000,providerInstanceId:'opencode',model:'test/model'}},
    {id:'b',host:'test-host',threadId:'thread-b',observeAfter:'2026-10-18T14:00:00Z'},
  ]};
  const data={thread:{threadId:'thread-a',activeRunId:null,latestRunId:'run-1',providerInstanceId:'opencode',model:'test/model',runtimeMode:'approval-required',status:'completed'},
    recentRuns:[{runId:'run-1',status:'completed',completedAt:new Date(now).toISOString()}],items:[],hasMore:false};
  const posts=[];
  const backend={read:async s=>s.id==='a'?structuredClone(data):{...structuredClone(data),thread:{...data.thread,threadId:'thread-b'}},followup:async()=>{sends++;return {threadId:'thread-a',messageId:'message-1',runId:'run-2'};}};
  const post=async(url,headers,body)=>{
    const p=JSON.parse(body);posts.push({url,headers,body});
    return {status:p.type==='verification'?200:code,body:p.type==='verification'?JSON.stringify({challenge:p.challenge}):''};
  };
  const bridge=new Bridge({store,backend,policy:()=>policy,post,now:()=>now});
  const p={name:'t3.task.finished',arguments:{session_id:'a'},delivery:{mode:'webhook',url:'https://callbacks.example.com/event',secret:'whsec_'+randomBytes(32).toString('base64')}};
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,key,dir,bridge,policy,backend,data,posts,p,token,get sends(){return sends;},code:v=>{code=v;},advance:ms=>{now+=ms;}};
}

test('authentication and session authorization fail closed',async t=>{
  const f=fixture(t);
  assert.equal(principalFor('Bearer '+f.token,f.policy),'eddie');
  for(const h of [undefined,'bad','Bearer wrong'])assert.equal(principalFor(h,f.policy),null);
  assert.deepEqual(f.bridge.sessions('eddie').map(s=>s.id),['a']);
  await assert.rejects(f.bridge.read('eddie','b'),/forbidden/);
  await assert.rejects(f.bridge.subscribe('attacker',f.p),/forbidden/);
  f.policy.principals[0].enabled=false;
  assert.equal(principalFor('Bearer '+f.token,f.policy),null);
});

test('persistent subscription identity, verification, refresh, rotation and unsubscribe',async t=>{
  const f=fixture(t), a=await f.bridge.subscribe('eddie',f.p),b=await f.bridge.subscribe('eddie',structuredClone(f.p));
  assert.equal(a.id,b.id);assert.equal(f.store.all('subscription').length,1);
  const raw=readFileSync(join(f.dir,'bridge.db-wal'));
  assert.equal(raw.includes(f.p.delivery.secret),false);
  const second=new Store(join(f.dir,'bridge.db'),f.key);
  assert.equal(second.get('subscription',a.id).secret,f.p.delivery.secret);second.close();
  f.p.delivery.secret='whsec_'+randomBytes(32).toString('base64');
  await f.bridge.subscribe('eddie',f.p);
  assert.ok(f.store.get('subscription',a.id).oldSecret);
  f.bridge.unsubscribe('eddie',f.p);f.bridge.unsubscribe('eddie',f.p);
  assert.equal(f.store.get('subscription',a.id).active,false);
});

test('MCP null lifetime persists in encrypted SQLite and standing events remain deliverable after reopen',async t=>{
  const f=fixture(t),p={...f.p,ttlMs:null},r=await f.bridge.subscribe('eddie',p);
  assert.equal(r.refreshBefore,null);
  const reopened=new Store(join(f.dir,'bridge.db'),f.key);
  try{
    assert.equal(reopened.get('subscription',r.id).expires,null);
    f.advance(3*86400000);f.data.recentRuns[0].completedAt=new Date(Date.now()+3*86400000).toISOString();
    const resumed=new Bridge({...f.bridge,store:reopened});f.posts.length=0;
    await resumed.observe();await resumed.deliver();assert.equal(f.posts.length,1);
    resumed.unsubscribe('eddie',p);assert.equal(reopened.get('subscription',r.id).active,false);
  }finally{reopened.close();}
});

test('nonexpiring subscriptions still count toward admission and explicit finite requests stay finite',async t=>{
  const f=fixture(t);
  for(let i=0;i<8;i++)assert.equal((await f.bridge.subscribe('eddie',{...f.p,ttlMs:null,delivery:{...f.p.delivery,url:'https://callbacks.example.com/standing-'+i}})).refreshBefore,null);
  await assert.rejects(f.bridge.subscribe('eddie',{...f.p,ttlMs:null}),/subscription_limit/);
  const existing={...f.p,ttlMs:60000,delivery:{...f.p.delivery,url:'https://callbacks.example.com/standing-0'}};
  const finite=await f.bridge.subscribe('eddie',existing);assert.ok(finite.refreshBefore);
  assert.equal(Date.parse(finite.refreshBefore)-f.store.get('subscription',finite.id).refreshedAt,60000);
  assert.equal(f.store.all('subscription').filter(s=>s.expires===null).length,7);
});

test('callback verification is signed and fails on wrong challenge',async t=>{
  const f=fixture(t);
  await f.bridge.subscribe('eddie',f.p);
  const p=f.posts[0];new Webhook(f.p.delivery.secret).verify(p.body,p.headers);
  f.bridge.post=async()=>({status:200,body:'{"challenge":"wrong"}'});
  f.advance(300001);
  await assert.rejects(f.bridge.subscribe('eddie',f.p),/challenge_failed/);
});

test('event filtering, duplicate source observations and duplicate delivery are idempotent',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);f.posts.length=0;
  await f.bridge.observe();await f.bridge.observe();
  assert.equal(f.store.all('delivery').length,1);
  f.code(503);await f.bridge.deliver();const first=f.posts[0];
  assert.equal(f.store.all('delivery')[0].status,'pending');
  f.advance(10000);f.code(204);await f.bridge.deliver();
  const second=f.posts[1];
  assert.equal(JSON.parse(first.body).data.session_id,'a');
  assert.equal(first.body,second.body);
  assert.equal(first.headers['webhook-id'],second.headers['webhook-id']);
  assert.notEqual(first.headers['webhook-signature'],second.headers['webhook-signature']);
  // Test-signing clock is fixed; validate with that clock, including tamper denial.
  const verifier=new Webhook(f.p.delivery.secret);
  verifier.verify(second.body,second.headers,new Date(Number(second.headers['webhook-timestamp'])*1000));
  assert.throws(()=>verifier.verify(second.body+' ',second.headers));
  assert.equal(f.store.all('delivery')[0].status,'acknowledged');
  assert.equal(f.sends,0); // delivery does not execute anything
  await f.bridge.deliver();assert.equal(f.posts.length,2);
});

test('running and historical tasks do not emit terminal events; success is native lifecycle only',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);
  f.data.recentRuns[0].status='running';f.data.recentRuns[0].completedAt=null;
  await f.bridge.observe();assert.equal(f.store.all('delivery').length,0);
  f.data.recentRuns[0].status='completed';f.data.recentRuns[0].completedAt='2026-10-18T15:01:00Z';
  await f.bridge.observe();assert.equal(f.store.all('delivery').length,1);
  f.data.recentRuns=[{runId:'ancient',status:'completed',completedAt:'2026-10-01T00:00:00Z'}];
  await f.bridge.observe();assert.equal(f.store.all('delivery').length,1);
});

for(const status of [301,410,413,400])test(`terminal HTTP ${status} is never retried`,async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);await f.bridge.observe();f.code(status);
  await f.bridge.deliver();f.advance(3600000);await f.bridge.deliver();
  assert.equal(f.store.all('delivery')[0].attempts,1);assert.equal(f.store.all('delivery')[0].status,'stopped');
});

test('transient delivery has six-attempt budget; expiry, revocation, unsubscribe stop sends',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',f.p);await f.bridge.observe();f.code(503);
  for(let i=0;i<7;i++){await f.bridge.deliver();f.advance(1000000);}
  assert.equal(f.store.all('delivery')[0].attempts,6);
  assert.equal(f.store.all('delivery')[0].status,'stopped');
  f.data.recentRuns[0].runId='revoked';await f.bridge.observe();f.policy.principals[0].enabled=false;
  const n=f.posts.length;await f.bridge.deliver();assert.equal(f.posts.length,n);
});

test('bounded follow-up has persistent idempotency, one-session budget and explicit receipt',async t=>{
  const f=fixture(t),request={session_id:'a',run_id:'run-1',request_id:randomUUID()};
  const a=await f.bridge.followup('eddie',request),b=await f.bridge.followup('eddie',request);
  assert.equal(f.sends,1);assert.deepEqual(a,b);assert.equal(a.status,'accepted');
  assert.equal(a.followupRunId,'run-2');assert.ok(FOLLOWUP.includes('Do not use tools'));
  assert.equal(f.bridge.sessions('eddie')[0].followup.remaining,0);
  await assert.rejects(f.bridge.followup('eddie',{...request,run_id:'other'}),/idempotency_conflict/);
  await assert.rejects(f.bridge.followup('eddie',{...request,request_id:randomUUID()}),/budget_exhausted/);
});

test('Codex, unsupervised runtime, stale source and expired grant cannot run follow-up',async t=>{
  const f=fixture(t),p={session_id:'a',run_id:'run-1',request_id:randomUUID()};
  f.data.thread.providerInstanceId='codex';await assert.rejects(f.bridge.followup('eddie',p),/boundary_denied/);
  f.data.thread.providerInstanceId='opencode';f.data.thread.runtimeMode='full-access';await assert.rejects(f.bridge.followup('eddie',p),/boundary_denied/);
  f.data.thread.runtimeMode='approval-required';f.data.thread.latestRunId='changed';await assert.rejects(f.bridge.followup('eddie',p),/boundary_denied/);
  f.advance(86400001);await assert.rejects(f.bridge.followup('eddie',p),/not_authorized/);assert.equal(f.sends,0);
});

test('uncertain send and restart never resend; concurrent calls share the single reservation',async t=>{
  const f=fixture(t),p={session_id:'a',run_id:'run-1',request_id:randomUUID()};let attempts=0;
  f.backend.followup=async()=>{attempts++;throw new Error('network response lost');};
  const results=await Promise.allSettled([f.bridge.followup('eddie',p),f.bridge.followup('eddie',p)]);
  assert.equal(attempts,1);assert.ok(results.some(r=>r.status==='fulfilled'));
  const second=new Store(join(f.dir,'bridge.db'),f.key);
  const restarted=new Bridge({...f.bridge,store:second});
  assert.equal((await restarted.followup('eddie',p)).status,'submission_uncertain');assert.equal(attempts,1);second.close();
});

test('callback SSRF defenses reject private addresses, redirects by design, and unapproved hosts',async()=>{
  for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1','fc00::1','192.0.2.1'])assert.equal(publicAddress(ip),false,ip);
  assert.equal(publicAddress('8.8.8.8'),true);
  for(const url of ['http://callbacks.example.com','https://evil.example','https://u:p@callbacks.example.com','https://callbacks.example.com:444'])assert.throws(()=>callbackUrl(url,['callbacks.example.com']));
  await assert.rejects(postWebhook('https://callbacks.example.com',{},'{}',['callbacks.example.com'],async()=>[{address:'127.0.0.1',family:4}]),/address_denied/);
});

test('MCP 2.0 authenticated discovery, tools and events through official SDK HTTP',async t=>{
  const f=fixture(t),server=httpServer(f.bridge);await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(()=>new Promise(r=>server.close(r)));
  const url=`http://127.0.0.1:${server.address().port}/mcp`;
  async function rpc(method,params={},auth=true){
    const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method,...(params.name?{'Mcp-Name':params.name}:{}),accept:'application/json, text/event-stream',...(auth?{authorization:'Bearer '+f.token}:{})},
      body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'test',version:'1'}}}})});
    return {status:r.status,body:await r.text()};
  }
  assert.equal((await rpc('server/discover',{},false)).status,401);
  const discovery=await rpc('server/discover');
  assert.equal(discovery.status,200,discovery.body);
  const d=JSON.parse(discovery.body);assert.ok(d.result.supportedVersions.includes('2026-07-28'),discovery.body);
  assert.ok(d.result.capabilities.events,discovery.body);
  const list=await rpc('tools/list');assert.equal(JSON.parse(list.body).result.tools.length,4,list.body);
  const events=await rpc('events/list');assert.equal(JSON.parse(events.body).result.events[0].name,'t3.task.finished',events.body);
  const result=await rpc('tools/call',{name:'list_sessions',arguments:{}});
  assert.ok(JSON.parse(result.body).result.structuredContent.sessions,result.body);
  const invalid=await rpc('events/subscribe',{...f.p,arguments:{session_id:'b'}});
  assert.ok(JSON.parse(invalid.body).error,invalid.body);
  const subscribed=await rpc('events/subscribe',f.p);
  assert.ok(JSON.parse(subscribed.body).result?.id,subscribed.body);
  const privateUrl='https://unapproved.example/private-callback?token=PRIVATE_CALLBACK_TOKEN';
  const refused=await rpc('events/subscribe',{...f.p,delivery:{...f.p.delivery,url:privateUrl}});
  assert.deepEqual(JSON.parse(refused.body).error.data,{reason:'callback_not_allowed',callbackHostname:'unapproved.example'});
  const audit=JSON.stringify(f.store.db.prepare('SELECT action,subject,outcome FROM audit').all());
  assert.ok(audit.includes('unapproved.example'));
  for(const secret of [privateUrl,'PRIVATE_CALLBACK_TOKEN',f.p.delivery.secret]) {
    assert.equal(audit.includes(secret),false);assert.equal(refused.body.includes(secret),false);
  }
  const unauthorized=await rpc('events/subscribe',{...f.p,arguments:{session_id:'b'},delivery:{...f.p.delivery,url:privateUrl}});
  assert.equal(JSON.parse(unauthorized.body).error.data.callbackHostname,undefined);
  const stopped=await rpc('events/unsubscribe',{...f.p,delivery:{mode:'webhook',url:f.p.delivery.url}});
  assert.equal(JSON.parse(stopped.body).error,undefined,stopped.body);
  const client=new Client({name:'official-sdk-test',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
  await client.connect(new StreamableHTTPClientTransport(new URL(url),{requestInit:{headers:{Authorization:'Bearer '+f.token}}}));
  assert.equal((await client.listTools()).tools.length,4);
  const result2=await client.callTool({name:'get_task_result',arguments:{session_id:'a',run_id:'run-1'}});
  assert.equal(result2.isError,undefined);assert.equal(result2.structuredContent.runs[0].status,'completed');
  const untrustedRun='sk-'+randomUUID();
  await client.callTool({name:'get_task_result',arguments:{session_id:'a',run_id:untrustedRun}});
  const runAudit=JSON.stringify(f.store.db.prepare("SELECT subject FROM audit WHERE action='result.run.read'").all());
  assert.ok(runAudit.includes('run-1'));assert.equal(runAudit.includes(untrustedRun),false);
  const denied=await client.callTool({name:'request_followup',arguments:{session_id:'a',run_id:'run-1',request_id:randomUUID(),action:'arbitrary_shell'}});
  assert.equal(denied.isError,true);
  await client.close();
});

test('receipt acknowledgement, observed running and native completed execution stay distinct',async t=>{
  const f=fixture(t),p={session_id:'a',run_id:'run-1',request_id:randomUUID()};
  assert.equal((await f.bridge.followup('eddie',p)).status,'accepted');
  f.data.recentRuns.unshift({runId:'run-2',status:'running',completedAt:null});
  assert.equal((await f.bridge.read('eddie','a')).followups[0].status,'running');
  f.data.recentRuns[0].status='completed';f.data.recentRuns[0].completedAt=new Date().toISOString();
  assert.equal((await f.bridge.read('eddie','a')).followups[0].status,'completed');
});

test('expiration and unsubscribe prevent pending deliveries and later events',async t=>{
  const f=fixture(t);await f.bridge.subscribe('eddie',{...f.p,ttlMs:60000});await f.bridge.observe();
  f.advance(60001);await f.bridge.deliver();assert.equal(f.store.all('delivery')[0].status,'revoked');
  await f.bridge.subscribe('eddie',f.p);f.bridge.unsubscribe('eddie',f.p);
  f.data.recentRuns[0].runId='new-run';await f.bridge.observe();
  assert.equal(f.store.all('delivery').length,1);
});

test('refresh cache expires, rotating secrets dual-sign then retire, and invalid secrets are denied',async t=>{
  const f=fixture(t),old=f.p.delivery.secret;
  await f.bridge.subscribe('eddie',f.p);await f.bridge.subscribe('eddie',f.p);
  assert.equal(f.posts.length,1);
  f.p.delivery.secret='whsec_'+randomBytes(32).toString('base64');
  await f.bridge.subscribe('eddie',f.p);await f.bridge.observe();await f.bridge.deliver();
  const p=f.posts.at(-1);
  new Webhook(old).verify(p.body,p.headers);new Webhook(f.p.delivery.secret).verify(p.body,p.headers);
  await assert.rejects(f.bridge.subscribe('eddie',{...f.p,delivery:{...f.p.delivery,secret:'whsec_abc'}}),/signing_key/);
  f.advance(300001);f.data.recentRuns[0].runId='post-rotation';await f.bridge.observe();await f.bridge.deliver();
  const last=f.posts.at(-1);assert.equal(last.headers['webhook-signature'].split(' ').length,1);
});

test('source identity mismatches and read-only source cannot acquire a write reservation',async t=>{
  const f=fixture(t);f.data.thread.threadId='wrong';await assert.rejects(f.bridge.read('eddie','a'),/identity_mismatch/);
  f.backend.supportsFollowup=false;
  await assert.rejects(f.bridge.followup('eddie',{session_id:'a',run_id:'run-1',request_id:randomUUID()}),/transport_not_authorized/);
  assert.equal(f.store.all('followup').length,0);assert.equal(f.sends,0);
});

test('failed native authorization or revoked grant during preflight does not reserve a follow-up',async t=>{
  const f=fixture(t),p={session_id:'a',run_id:'run-1',request_id:randomUUID()};
  f.backend.preflight=async()=>{throw new Error('native_auth_denied');};
  await assert.rejects(f.bridge.followup('eddie',p),/auth_denied/);
  assert.equal(f.store.all('followup').length,0);
  f.backend.preflight=async()=>{delete f.policy.sessions[0].followup;};
  await assert.rejects(f.bridge.followup('eddie',p),/grant_changed/);
  assert.equal(f.store.all('followup').length,0);assert.equal(f.sends,0);
});

test('daily allowance renews for new source runs, never repeats a source or follows its own result',async t=>{
  const f=fixture(t);f.policy.sessions[0].followup.expiresAt+=3*86400000;
  await f.bridge.followup('eddie',{session_id:'a',run_id:'run-1',request_id:randomUUID()});
  f.data.thread.latestRunId='run-2';f.data.recentRuns.unshift({runId:'run-2',status:'completed',completedAt:new Date().toISOString()});
  await assert.rejects(f.bridge.followup('eddie',{session_id:'a',run_id:'run-2',request_id:randomUUID()}),/followup_of_followup_denied/);
  f.data.thread.latestRunId='external-run';f.data.recentRuns.unshift({runId:'external-run',status:'completed',completedAt:new Date().toISOString()});
  await assert.rejects(f.bridge.followup('eddie',{session_id:'a',run_id:'external-run',request_id:randomUUID()}),/budget_exhausted/);
  f.advance(86400001);
  assert.equal(f.bridge.sessions('eddie')[0].followup.remaining,1);
  await f.bridge.followup('eddie',{session_id:'a',run_id:'external-run',request_id:randomUUID()});
  assert.equal(f.sends,2);
  await assert.rejects(f.bridge.followup('eddie',{session_id:'a',run_id:'external-run',request_id:randomUUID()}),/budget_exhausted/);
});


test('inbox status is owner-only secret-free observation; protocol refresh preserves identity and grants',async t=>{
 const f=fixture(t);f.policy.principals[0].eddieInbox=true;
 const p={name:'t3.eddie.requested',arguments:{inbox_id:'eddie'},delivery:f.p.delivery,ttlMs:2000};
 const policy=JSON.stringify(f.policy);const first=await f.bridge.subscribe('eddie',p);const before=JSON.stringify(f.store.all('subscription'));
 const status=f.bridge.inboxSubscriptions('eddie');assert.equal(status.subscriptions[0].active,true);assert.equal(status.subscriptions[0].refresh_before,first.refreshBefore);assert.equal(JSON.stringify(f.store.all('subscription')),before);
 for(const secret of [p.delivery.url,p.delivery.secret,'oldSecret','rotateUntil'])assert.equal(JSON.stringify(status).includes(secret),false);
 assert.throws(()=>f.bridge.inboxSubscriptions('reader'),/forbidden/);f.policy.principals.push({id:'other-inbox',eddieInbox:true,sessions:[]});assert.deepEqual(f.bridge.inboxSubscriptions('other-inbox').subscriptions,[]);f.policy.principals.pop();
 f.advance(1000);const refreshed=await f.bridge.subscribe('eddie',{...p,ttlMs:3000});assert.equal(refreshed.id,first.id);assert.ok(refreshed.refreshBefore>first.refreshBefore);assert.equal(f.store.all('subscription').length,1);assert.equal(JSON.stringify(f.policy),policy);
 f.advance(4000);assert.equal(f.bridge.inboxSubscriptions('eddie').subscriptions[0].state,'expired');f.policy.principals[0].enabled=false;assert.throws(()=>f.bridge.inboxSubscriptions('eddie'),/forbidden/);
});
