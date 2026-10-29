// SPDX-License-Identifier: AGPL-3.0-or-later
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import {registerPiEddie} from '../scripts/pi-eddie.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {Store} from '../src/store.mjs';
import {Bridge} from '../src/bridge.mjs';
import {HostCallers} from '../src/host-callers.mjs';
import {hostCallerOwner} from '../src/host-caller-scope.mjs';
import {httpServer} from '../src/server.mjs';
import {configSchema} from '../src/config.mjs';
function fixture(t){
 const store=new Store(':memory:',randomBytes(32)),token=randomBytes(32).toString('base64');let hook=()=>{},now=Date.now();
 const policy={stateDirectory:'unused',source:{type:'local-projection',databasePath:'unused'},sessions:[],callbackHosts:['callbacks.example.com'],fleetRead:{hosts:[{name:'local'}]},principals:[
  {id:'eddie',tokenSha256:'a'.repeat(64),sessions:[],eddieInbox:true,readHosts:[{host:'local',projectIds:['p']}]},
  {id:'agents',tokenSha256:createHash('sha256').update(token).digest('hex'),sessions:[],eddieHostCaller:{host:'local',reviewer:'eddie',expiresAt:now+60000,maxPerDay:10}}
 ]};
 const reads=[],threads=Object.fromEntries(['codex','claude','pi','opencode','subagent'].map(id=>[id,{thread:{threadId:id,projectId:'p',activeRunId:'run-'+id,providerInstanceId:id},runs:[{runId:'run-'+id,status:'running'}]}]));
 const bridge=new Bridge({store,policy:()=>policy,now:()=>now,backend:{},post:async(_u,_h,b)=>({status:200,body:JSON.stringify({challenge:JSON.parse(b).challenge})})});
 bridge.fleetReads={grant(owner,host,project){const g=policy.principals[0].readHosts.find(g=>g.host===host);if(owner!=='eddie'||policy.principals[0].enabled===false||!g||project&&g.projectIds&&!g.projectIds.includes(project))throw Object.assign(Error('forbidden'),{reason:'forbidden'});},async read(owner,{host,thread_id}){this.grant(owner,host);reads.push(thread_id);await hook();const p=threads[thread_id];if(!p)throw Object.assign(Error('thread_not_found'),{reason:'thread_not_found'});this.grant(owner,host,p.thread.projectId);return p;}};
 const callers=new HostCallers(bridge),ask=thread_id=>({thread_id,request_id:randomUUID(),question:'A passive question.'});
 t.after(()=>store.close());return{bridge,store,policy,token,threads,reads,callers,ask,advance:ms=>now+=ms,hook:f=>hook=f};
}

test('any provider and subagent can ask without enrollment; native run and host are server-derived',async t=>{
 const f=fixture(t);
 for(const id of Object.keys(f.threads)){
  const p=f.ask(id),r=await f.callers.ask('agents',p);
  assert.equal(r.thread_id,id);assert.equal(r.host,'local');assert.equal(r.run_id,'run-'+id);assert.equal(r.resumes_t3,false);
  assert.equal(r.delivery.state,'awaiting_subscription');
  assert.deepEqual(await f.callers.ask('agents',p),r);
 }
 assert.equal(f.policy.principals.length,2);assert.equal(f.store.all('exchange').length,5);assert.equal(f.store.all('command').length,0);
 await assert.rejects(f.callers.ask('agents',{...f.ask('codex'),host:'other'}));
 await assert.rejects(f.callers.ask('agents',{...f.ask('codex'),run_id:'spoofed'}));
 await assert.rejects(f.callers.ask('agents',f.ask('missing')),/thread_not_found/);
 f.threads.codex.thread.activeRunId=null;await assert.rejects(f.callers.ask('agents',f.ask('codex')),/source_run_not_active/);
});

test('requests and conversations are bound to their declared thread; host callers cannot acquire inbox tools or cross a project boundary',async t=>{
 const f=fixture(t),a=f.ask('codex'),b=f.ask('subagent');await f.callers.ask('agents',a);await f.callers.ask('agents',b);
 await assert.rejects(f.callers.get('agents',{thread_id:'subagent',request_id:a.request_id}),/forbidden/);
 await assert.rejects(f.callers.conversation('agents',{thread_id:'subagent',conversation_id:a.request_id}),/forbidden/);
 await assert.rejects(f.bridge.exchanges.list('agents'),/forbidden/);
 f.threads.codex.thread.projectId='secret';await assert.rejects(f.callers.get('agents',{thread_id:'codex',request_id:a.request_id}),/forbidden/);
 assert.equal(f.store.all('command').length,0);
});

test('host revocation, rebinding, expiry and reviewer revocation invalidate derived identities and prevent pending delivery',async t=>{
 const f=fixture(t),p=f.ask('codex');await f.callers.ask('agents',p);
 for(const mutate of [()=>f.policy.principals[1].enabled=false,()=>f.policy.principals[1].eddieHostCaller.host='other',()=>f.policy.principals[1].eddieHostCaller.reviewer='other',()=>f.policy.principals[0].enabled=false]){
  const saved=structuredClone(f.policy.principals);mutate();
  await assert.rejects(f.callers.get('agents',{thread_id:'codex',request_id:p.request_id}),/forbidden/);
  await assert.rejects(f.bridge.exchanges.get('eddie',{request_id:p.request_id},{reviewer:true}),/forbidden/);
  f.policy.principals=saved;
 }
 f.advance(60001);await assert.rejects(f.callers.get('agents',{thread_id:'codex',request_id:p.request_id}),/forbidden/);
});

test('host scope rechecks after native I/O, duplicate calls remain one-shot across run changes and conversations stay thread-bound',async t=>{
 const f=fixture(t),p=f.ask('codex');
 f.hook(()=>{f.policy.principals[1].enabled=false;});await assert.rejects(f.callers.ask('agents',p),/forbidden/);assert.equal(f.store.all('exchange').length,0);
 f.hook(()=>{});f.policy.principals[1].enabled=true;
 await Promise.all([f.callers.ask('agents',p),f.callers.ask('agents',p)]);assert.equal(f.store.all('exchange').length,1);
 f.threads.codex.thread.activeRunId='new-run';f.threads.codex.runs=[{runId:'new-run',status:'running'}];
 assert.equal((await f.callers.ask('agents',p)).run_id,'run-codex');
 await assert.rejects(f.callers.ask('agents',{...p,question:'changed'}),/idempotency_conflict/);
 await f.bridge.exchanges.get('eddie',{request_id:p.request_id},{reviewer:true});await f.bridge.exchanges.reply('eddie',{request_id:p.request_id,reply:'Answer'});
 const next={...f.ask('codex'),conversation_id:p.request_id,in_reply_to:p.request_id};assert.equal((await f.callers.ask('agents',next)).sequence,2);
 await assert.rejects(f.callers.ask('agents',{...next,...f.ask('subagent')}),/forbidden/);
 assert.equal((await f.callers.conversation('agents',{thread_id:'codex',conversation_id:p.request_id})).requests.length,2);
});

test('passive fair-use limits remain per thread, and the inbox catches up unsent requests without per-thread subscriptions',async t=>{
 const f=fixture(t);f.policy.principals[1].eddieHostCaller.maxPerDay=1;
 const p=f.ask('codex');await f.callers.ask('agents',p);
 await assert.rejects(f.callers.ask('agents',f.ask('codex')),/exchange_budget_exhausted/);
 await f.callers.ask('agents',f.ask('subagent'));
 const sub=await f.bridge.subscribe('eddie',{name:'t3.eddie.requested',arguments:{inbox_id:'eddie'},delivery:{mode:'webhook',url:'https://callbacks.example.com/event',secret:'whsec_'+randomBytes(32).toString('base64')}});
 assert.equal(f.store.all('subscription')[0].name,'t3.eddie.requested');assert.equal(f.store.all('delivery').length,2);
 await f.bridge.deliver();assert.ok(f.store.all('delivery').every(d=>d.status==='acknowledged'));
 const read=await f.bridge.exchanges.get('eddie',{request_id:p.request_id},{reviewer:true});assert.equal(read.thread_id,'codex');
});

test('bounded wait returns an exact authorized reply without repeated native polling or resumption',async t=>{
 const f=fixture(t),p=f.ask('codex');await f.bridge.subscribe('eddie',{name:'t3.eddie.requested',arguments:{inbox_id:'eddie'},delivery:{mode:'webhook',url:'https://callbacks.example.com/event',secret:'whsec_'+randomBytes(32).toString('base64')}});
 const request=f.callers.ask('agents',{...p,wait_ms:1000});
 await new Promise(r=>setTimeout(r,30));
 await f.bridge.exchanges.get('eddie',{request_id:p.request_id},{reviewer:true});await f.bridge.exchanges.reply('eddie',{request_id:p.request_id,reply:'WAIT_OK'});
 assert.equal((await request).reply,'WAIT_OK');assert.equal(f.store.all('exchange').length,1);assert.equal(f.store.all('command').length,0);assert.ok(f.reads.length<=5);
});

test('official MCP and stdio expose only passive tools with the host schema and no claimed run ID',async t=>{
 const f=fixture(t),server=httpServer(f.bridge);await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const endpoint=`http://127.0.0.1:${server.address().port}/mcp`,client=new Client({name:'host-test',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
 t.after(async()=>{await client.close();await new Promise(r=>server.close(r));});
 await client.connect(new StreamableHTTPClientTransport(new URL(endpoint),{requestInit:{headers:{Authorization:'Bearer '+f.token}}}));
 const tools=(await client.listTools()).tools;
 assert.deepEqual(tools.map(t=>t.name).sort(),['acknowledge_eddie_reply','ask_eddie','get_eddie_capabilities','get_eddie_conversation','get_eddie_reply']);
 assert.equal(tools.find(t=>t.name==='ask_eddie').inputSchema.properties.run_id,undefined);
 assert.equal((await client.callTool({name:'get_eddie_capabilities',arguments:{}})).structuredContent.host_caller,true);
 const stdio=new Client({name:'host-stdio',version:'1'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});t.after(()=>stdio.close());
 await stdio.connect(new StdioClientTransport({command:process.execPath,args:['scripts/caller-mcp.mjs'],env:{...process.env,EDDIE_T3_CALLER_TOKEN:f.token,EDDIE_T3_CALLER_ENDPOINT:endpoint},stderr:'pipe'}));
 const asked=await stdio.callTool({name:'ask_eddie',arguments:f.ask('codex')});assert.equal(asked.structuredContent.run_id,'run-codex');
});

test('policy permits separate passive host callers only and reserves derived principal identities',()=>{
 const f={stateDirectory:'x',source:{type:'local-projection',databasePath:'x'},sessions:[],callbackHosts:[],fleetRead:{hosts:[{name:'local'}]},principals:[{id:'eddie',sessions:[],tokenSha256:'a'.repeat(64),eddieInbox:true,readHosts:[{host:'local'}]},{id:'agents',sessions:[],tokenSha256:'b'.repeat(64),eddieHostCaller:{host:'local',reviewer:'eddie',expiresAt:1}}]};
 assert.equal(configSchema.safeParse(f).success,true);
 for(const mutate of [p=>p.principals[1].eddieInbox=true,p=>p.principals[1].readHosts=[{host:'local'}],p=>p.principals[1].eddieHostCaller.host='other',p=>p.principals[1].id=hostCallerOwner('agents','codex'),p=>p.principals[1].eddieCaller={...p.principals[1].eddieHostCaller,threadId:'t'}]){
  const p=structuredClone(f);mutate(p);assert.equal(configSchema.safeParse(p).success,false);
 }
});


test('universal CLI and native Pi tools use the same host-scoped MCP exchange and never leak their credential',async t=>{
 const f=fixture(t),server=httpServer(f.bridge);await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const dir=mkdtempSync(join(tmpdir(),'eddie-agent-')),launch=join(dir,'launch.mjs'),connection=join(dir,'connection.json'),input=join(dir,'input.json');
 const endpoint=`http://127.0.0.1:${server.address().port}/mcp`;
 writeFileSync(launch,`process.env.EDDIE_T3_CALLER_TOKEN=${JSON.stringify(f.token)};process.env.EDDIE_T3_CALLER_ENDPOINT=${JSON.stringify(endpoint)};await import(${JSON.stringify(pathToFileURL(resolve('scripts/caller-mcp.mjs')).href)});`,{mode:0o600});
 writeFileSync(connection,JSON.stringify({host:'local',command:process.execPath,args:[launch]}));
 t.after(async()=>{await new Promise(r=>server.close(r));rmSync(dir,{recursive:true,force:true});});
 const run=async(mode,data)=>{
  writeFileSync(input,JSON.stringify(data));const child=spawn(process.execPath,['scripts/agent-tool.mjs',connection,mode,input],{windowsHide:true,stdio:['ignore','pipe','pipe']});
  let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);
  const code=await new Promise((resolve,reject)=>{child.once('exit',resolve);child.once('error',reject);});assert.equal(code,0,err);assert.equal((out+err).includes(f.token),false);return JSON.parse(out);
 };
 const p=f.ask('codex');assert.equal((await run('ask',p)).run_id,'run-codex');
 await f.bridge.exchanges.get('eddie',{request_id:p.request_id},{reviewer:true});await f.bridge.exchanges.reply('eddie',{request_id:p.request_id,reply:'CLI_REPLY_OK'});
 assert.equal((await run('get',{thread_id:'codex',request_id:p.request_id})).reply,'CLI_REPLY_OK');
 const tools={},handlers={},pi={registerTool:t=>tools[t.name]=t,on:(name,fn)=>handlers[name]=fn};
 const Type={String:o=>({type:'string',...o}),Integer:o=>({type:'integer',...o}),Optional:o=>o,Object:(p,o)=>({type:'object',properties:p,...o})};
 registerPiEddie(pi,Type,connection);assert.equal(Object.keys(tools).length,5);
 const q=f.ask('pi'),asked=await tools.ask_eddie.execute('tool-call',q);assert.equal(asked.details.run_id,'run-pi');
 await f.bridge.exchanges.get('eddie',{request_id:q.request_id},{reviewer:true});await f.bridge.exchanges.reply('eddie',{request_id:q.request_id,reply:'PI_REPLY_OK'});
 const reply=await tools.get_eddie_reply.execute('tool-read',{thread_id:'pi',request_id:q.request_id});assert.equal(reply.details.reply,'PI_REPLY_OK');assert.equal(reply.details.resumes_t3,false);
 await handlers.session_shutdown();assert.equal(f.store.all('exchange').length,2);assert.equal(f.store.all('command').length,0);
});
