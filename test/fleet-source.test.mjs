// SPDX-License-Identifier: AGPL-3.0-or-later
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {Store} from '../src/store.mjs';
import {Bridge} from '../src/bridge.mjs';
import {configSchema} from '../src/config.mjs';
import {withFleetSessions} from '../src/fleet-source.mjs';

function fixture(t) {
  const store=new Store(':memory:',randomBytes(32));t.after(()=>store.close());
  const session={id:'pilot',host:'remote',threadId:'thread',observeAfter:'2026-10-20T00:00:00Z'};
  const policy={source:{type:'local-projection',databasePath:'db'},stateDirectory:'.',
    fleetRead:{hosts:[{name:'remote'}]},callbackHosts:['callbacks.example.com'],sessions:[session],
    principals:[{id:'eddie',tokenSha256:'a'.repeat(64),sessions:['pilot'],readHosts:[{host:'remote'}]},
      {id:'other',tokenSha256:'b'.repeat(64),sessions:[],readHosts:[{host:'remote'}]}]};
  const calls=[],data={thread:{threadId:'thread',projectId:'project'},runs:[],items:[],hasMore:false,nextPosition:null};
  const reader={read:async(owner,p)=>{calls.push({owner,...p});return structuredClone(data);}};
  const local={supportsFollowup:true,read:async(...args)=>({local:args}),followup:async()=>{throw new Error('unexpected_write');}};
  const backend=withFleetSessions(local,reader,()=>policy),posts=[];
  const bridge=new Bridge({store,backend,policy:()=>policy,post:async(_url,_headers,body)=>{
    const event=JSON.parse(body);posts.push(event);
    return {status:200,body:JSON.stringify({challenge:event.challenge})};
  }});
  return {store,session,policy,calls,data,backend,bridge,posts};
}

test('remote enrollment requires a read route/grant and never enables legacy followup',async t=>{
  const f=fixture(t);assert.ok(configSchema.safeParse(f.policy).success);
  const check=mutate=>{const p=structuredClone(f.policy);mutate(p);assert.equal(configSchema.safeParse(p).success,false);};
  check(p=>delete p.fleetRead);
  check(p=>p.principals[0].readHosts=[]);
  check(p=>p.sessions[0].followup={action:'verify_result',dedicated:true,maxPerDay:1,expiresAt:Date.now()+10000,providerInstanceId:'opencode',model:'test'});
  assert.throws(()=>f.backend.followup(f.session),/remote_followup_not_authorized/);
  assert.equal(f.calls.length,0);
});

test('remote reads use exact owner/thread and preserve pagination; unauthorized reads never hit transport',async t=>{
  const f=fixture(t);f.data.runs=[{runId:'r',status:'completed'}];f.data.items=[{runId:'r',text:'yes'},{runId:'other',text:'no'}];
  const data=await f.bridge.read('eddie','pilot',true,{runId:'r',afterPosition:25});
  assert.deepEqual(f.calls,[{owner:'eddie',host:'remote',thread_id:'thread',view:'activity',after_position:25}]);
  assert.deepEqual(data.recentRuns,f.data.runs);assert.equal(data.items.length,1);
  await assert.rejects(f.bridge.read('other','pilot'),/forbidden/);
  await assert.rejects(f.backend.read({...f.session,threadId:'other'}),/forbidden/);
  f.policy.principals[0].enabled=false;
  await assert.rejects(f.backend.read(f.session),/forbidden/);
  assert.equal(f.calls.length,1);
  const local=await f.backend.read({host:'local',threadId:'local'},true,{afterPosition:3});
  assert.equal(local.local[1],true);assert.equal(local.local[2].afterPosition,3);
});

test('successive remote runs emit exact deduplicated events without executing work; outage recovers',async t=>{
  const f=fixture(t);
  await f.bridge.subscribe('eddie',{name:'t3.task.finished',arguments:{session_id:'pilot'},
    delivery:{mode:'webhook',url:'https://callbacks.example.com/event',secret:'whsec_'+randomBytes(32).toString('base64')}});
  f.posts.length=0;
  f.data.runs=[{runId:'run1',status:'running',completedAt:null}];
  await f.bridge.observe();assert.equal(f.store.all('delivery').length,0);
  f.data.runs[0]={runId:'run1',status:'completed',completedAt:new Date().toISOString()};
  await f.bridge.observe();await f.bridge.observe();await f.bridge.deliver();
  f.data.runs.unshift({runId:'run2',status:'failed',completedAt:new Date().toISOString()});
  const read=f.backend.read;f.backend.read=async()=>{throw new Error('offline');};
  await f.bridge.observe();assert.equal(f.store.all('delivery').length,1);
  f.backend.read=read;await f.bridge.observe();await f.bridge.deliver();
  assert.deepEqual(f.posts.map(e=>e.data),[
    {session_id:'pilot',run_id:'run1',status:'completed'},
    {session_id:'pilot',run_id:'run2',status:'failed'}]);
  assert.equal(f.store.all('delivery').length,2);
  f.policy.principals[0].sessions=[];f.data.runs.unshift({runId:'run3',status:'completed',completedAt:new Date().toISOString()});
  await f.bridge.observe();assert.equal(f.store.all('delivery').length,2);
});
