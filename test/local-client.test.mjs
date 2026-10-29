// SPDX-License-Identifier: AGPL-3.0-or-later
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,utimesSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {localClientOptions,withLocalFollowup} from '../src/local-client.mjs';
import {fleetBackend} from '../src/backend.mjs';

test('existing local credential is reused only at its enrolled loopback origin and never renewed',t=>{
  const dir=mkdtempSync(join(tmpdir(),'t3-client-')),tokenFile=join(dir,'existing.token'),now=Date.now();
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const config={origin:'http://127.0.0.1:3773',tokenFile};
  const claims={sub:'mcp-client',exp:now+1800000,scopes:['orchestration:read','orchestration:operate']};
  const save=c=>{const token=Buffer.from(JSON.stringify(c)).toString('base64url')+'.'+'s'.repeat(64);writeFileSync(tokenFile,token);return token;};
  const token=save(claims),options=localClientOptions(config,()=>now);
  assert.deepEqual(options.hostsProvider(),{hosts:[{name:'local',url:config.origin+'/mcp'}]});
  const entry=Object.values(options.cacheProvider())[0];
  assert.equal(entry.token,token);assert.equal(entry.access,'approval-required');assert.equal(entry.expiresAt,claims.exp);
  for(const c of [{...claims,sub:'browser'},{...claims,exp:now+1000},{...claims,scopes:['orchestration:read']}]) {
    save(c);assert.throws(()=>options.cacheProvider(),e=>e.message==='existing_local_credential_unavailable_or_stale'&&!e.message.includes(token));
  }
  save({...claims,scopes:['orchestration:read']});
  const read=localClientOptions(config,()=>now,'read','lt002');
  assert.deepEqual(read.hostsProvider().hosts.map(h=>h.name),['lt002']);
  assert.deepEqual(Object.values(read.cacheProvider())[0].scopes,['orchestration:read']);
  save(claims);utimesSync(tokenFile,new Date(now-1200001),new Date(now-1200001));
  assert.throws(()=>options.cacheProvider(),/stale/);
  for(const origin of ['https://127.0.0.1:3773','http://localhost:3773','http://evil.example:3773','http://127.0.0.1:3773/path','http://u:p@127.0.0.1:3773'])
    assert.throws(()=>localClientOptions({...config,origin}),/origin_denied/);
});

test('native follow-up rechecks provider, model, runtime and source run; closes transport after denial',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'t3-write-')),helper=join(dir,'helper.mjs');t.after(()=>rmSync(dir,{recursive:true,force:true}));
  writeFileSync(helper,`export class T3FleetTransport {
    constructor(options){this.test=options.test;}
    async connect(host,scope){this.test.opens.push([host,scope]);return {readThread:async()=>({thread:this.test.thread}),sendThreadMessage:async input=>{this.test.sends.push(input);return {threadId:input.threadId,messageId:'m'};}};}
    async close(){this.test.closes++;}
  }`);
  const state={thread:{threadId:'t',activeRunId:null,latestRunId:'r',providerInstanceId:'opencode',model:'m',runtimeMode:'approval-required'},opens:[],sends:[],closes:0};
  const backend=await fleetBackend(helper,{test:state}),session={host:'local',threadId:'t',followup:{providerInstanceId:'opencode',model:'m'}};
  const initial={...state.thread};
  for(const change of [{providerInstanceId:'codex'},{model:'other'},{runtimeMode:'full-access'},{latestRunId:'new'},{activeRunId:'active'},{threadId:'wrong'}]) {
    state.thread={...initial,...change};await assert.rejects(backend.followup(session,'fixed','uuid','r'),/boundary_changed/);
  }
  assert.equal(state.sends.length,0);assert.equal(state.closes,6);
  state.thread=initial;await backend.followup(session,'fixed','uuid','r');
  assert.deepEqual(state.sends,[{threadId:'t',message:'fixed',mode:'queue',clientRequestId:'uuid'}]);assert.equal(state.closes,7);
});

test('hybrid local source retrieves real activity through native MCP and keeps projection reads separate',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'t3-activity-')),helper=join(dir,'helper.mjs');t.after(()=>rmSync(dir,{recursive:true,force:true}));
  writeFileSync(helper,`export class T3FleetTransport {
    async connect(){return {readThread:async input=>({thread:{threadId:input.threadId},items:[{text:input.view}],recentRuns:[]})};}
    async close(){}
  }`);
  let closed=false;
  const source={read:async()=>({source:'read-only-projection'}),close:()=>{closed=true;}};
  const backend=await withLocalFollowup(source,helper,{origin:'http://127.0.0.1:3773',tokenFile:'not-used-by-fake'});
  assert.equal((await backend.read({host:'local',threadId:'t'},false)).source,'read-only-projection');
  assert.equal((await backend.read({host:'local',threadId:'t'},true)).items[0].text,'activity');
  await backend.close();assert.equal(closed,true);
});
