// SPDX-License-Identifier: AGPL-3.0-or-later
import {readReason,transientReadReasons} from './read-errors.mjs';
import {localClientOptions} from './local-client.mjs';
import {T3FleetTransport} from './fleet-transport-read.mjs';
import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {diagnose} from './diagnostics.mjs';

// The fleet reader receives only read handles from the existing reviewed helper.
// It has no send, delegation, auth bootstrap, source-DB write or event-enrollment path.
export const scrub=text=>String(text??'').replace(/\b(?:sk-[\w-]{12,}|Bearer\s+[\w.~-]+|whsec_[\w+/=]+)\b/gi,'[REDACTED]');
const fields=(value,names)=>Object.fromEntries(names.filter(k=>value?.[k]!==undefined).map(k=>[k,typeof value[k]==='string'?scrub(value[k]):value[k]]));
const failure=reason=>Object.assign(new Error(reason),{reason});
const reasonFor=readReason;

export class FleetReader {
  constructor({policy,audit,transport,cursorKey=randomBytes(32)}) {Object.assign(this,{policy,audit,transport,cursorKey});this.tails=new Map();this.active=new Set();this.stopped=false;}
  cursor(state) {
    const payload=Buffer.from(JSON.stringify(state)).toString('base64url');
    return payload+'.'+createHmac('sha256',this.cursorKey).update(payload).digest('base64url');
  }
  grant(owner,host,projectId) {
    const p=this.policy(),principal=p.principals.find(x=>x.id===owner&&x.enabled!==false);
    const route=p.fleetRead?.hosts.find(x=>x.name===host),grant=principal?.readHosts?.find(x=>x.host===host);
    if(!route||!grant||projectId!==undefined&&grant.projectIds&&!grant.projectIds.includes(projectId))throw failure('forbidden');
    return {route,grant};
  }
  hosts(owner) {
    const p=this.policy(),principal=p.principals.find(x=>x.id===owner&&x.enabled!==false);
    if(!principal)throw failure('forbidden');
    this.audit('fleet.hosts',owner,'returned');
    return {hosts:(principal.readHosts??[]).map(g=>{this.grant(owner,g.host);return {host:g.host,projectIds:g.projectIds??null,access:'read-only',availability:'not_checked'};}),
      discovery:'paginated_project_and_thread_inventory',inventoryInstructions:'Call inventory_threads for EVERY host, continuing each next_cursor until null, even after an empty page. Include all returned subagents/settled threads. There is no total inventory cap. Search is optional and non-exhaustive.'};
  }
  async inventory(owner,{host,cursor}) {
    const {grant}=this.grant(owner,host);
    const scope=createHash('sha256').update(JSON.stringify(grant)).digest('hex');
    let state={version:1,owner,host,scope,projectOffset:0,threadOffset:0,projectId:null};
    if(cursor) {
      try {
        const [payload,signature,...extra]=cursor.split('.');
        const expected=createHmac('sha256',this.cursorKey).update(payload).digest(),actual=Buffer.from(signature??'','base64url');
        if(extra.length||expected.length!==actual.length||!timingSafeEqual(expected,actual))throw new Error();
        const parsed=JSON.parse(Buffer.from(payload,'base64url').toString());
        if(parsed.version!==1||parsed.owner!==owner||parsed.host!==host||parsed.scope!==scope
          ||!Number.isSafeInteger(parsed.projectOffset)||parsed.projectOffset<0||!Number.isSafeInteger(parsed.threadOffset)||parsed.threadOffset<0
          ||!(parsed.projectId===null||typeof parsed.projectId==='string'))throw new Error();
        state=parsed;
      }catch{throw failure('invalid_inventory_cursor');}
    }
    return this.withHost(owner,host,undefined,async client=>{
      const startedAt=new Date().toISOString(),deadline=Date.now()+20000,threads=[],projects=[];let complete=false;
      let page=await client.listProjects({cursor:state.projectOffset,limit:100});
      if(!Array.isArray(page.projects)||page.nextCursor!==null&&!Number.isSafeInteger(page.nextCursor))throw failure('source_unavailable');
      if(state.projectId!==null&&page.projects.length===0)throw failure('inventory_changed');
      let index=0,pageStart=state.projectOffset;
      while(true) {
        if(index>=page.projects.length) {
          if(page.nextCursor===null){complete=true;break;}
          if(page.nextCursor<=pageStart)throw failure('source_unavailable');
          state.projectOffset=page.nextCursor;state.projectId=null;state.threadOffset=0;
          if(threads.length>=100||projects.length>=100||Date.now()>=deadline)break;
          pageStart=state.projectOffset;page=await client.listProjects({cursor:state.projectOffset,limit:100});index=0;
          if(!Array.isArray(page.projects)||page.nextCursor!==null&&!Number.isSafeInteger(page.nextCursor))throw failure('source_unavailable');
          continue;
        }
        const project=page.projects[index];
        if(typeof project.id!=='string'||!project.id)throw failure('identity_mismatch');
        if(state.projectId!==null&&state.projectId!==project.id)throw failure('inventory_changed');
        if(threads.length>=100||projects.length>=100||Date.now()>=deadline)break;
        const current=this.grant(owner,host);
        if(current.grant.projectIds&&!current.grant.projectIds.includes(project.id)) {
          state.projectOffset++;state.projectId=null;state.threadOffset=0;index++;continue;
        }
        const data=await client.listThreads({projectId:project.id,cursor:state.threadOffset,limit:100-threads.length,includeSubagents:true,settled:null,snoozed:null});
        this.grant(owner,host,project.id);
        if(data.projectId!==project.id||!Array.isArray(data.threads)||data.threads.length>100-threads.length
          ||!Number.isSafeInteger(data.total)||data.total<0)throw failure('identity_mismatch');
        projects.push({...fields(project,['id','title']),threadTotal:data.total});
        for(const thread of data.threads) {
          if(typeof thread.threadId!=='string')throw failure('identity_mismatch');
          threads.push({projectId:project.id,projectTitle:scrub(project.title),...fields(thread,['threadId','title','status','providerInstanceId','model','runtimeMode','latestRunId','parentThreadId','relationshipToParent','settled','settledAt','snoozed','snoozedUntil','createdAt','updatedAt'])});
        }
        if(data.nextCursor!==null) {
          if(!Number.isSafeInteger(data.nextCursor)||data.nextCursor<=state.threadOffset)throw failure('source_unavailable');
          state.threadOffset=data.nextCursor;state.projectId=project.id;
        }else{state.projectOffset++;state.projectId=null;state.threadOffset=0;index++;}
      }
      const final=this.grant(owner,host).grant;
      if(createHash('sha256').update(JSON.stringify(final)).digest('hex')!==scope)throw failure('forbidden');
      this.audit('fleet.inventory',`${owner}:${host}`,complete?'complete':'page');
      return {host,startedAt,finishedAt:new Date().toISOString(),projects,threads,
        next_cursor:complete?null:this.cursor(state),complete,
        coverage:'All native registered projects and their threads, including subagents, settled and snoozed threads; no total cap. Deleted records are outside the native inventory.',
        consistency:'Live enumeration, not an atomic fleet snapshot. Continue every next_cursor until null, even on empty pages. Deduplicate by host/threadId. Repeat if projects/threads change while paging.'};
    }).catch(error=>{const reason=reasonFor(error);this.audit('fleet.inventory',`${owner}:${host}`,reason);throw failure(reason);});
  }
  async withHost(owner,host,projectId,fn) {
    this.grant(owner,host,projectId);
    if(this.stopped)throw failure('source_unavailable');
    const previous=this.tails.get(host)??Promise.resolve();
    const work=previous.catch(()=>{}).then(async()=>{
      const {route}=this.grant(owner,host,projectId);
      const t=this.transport(route);this.active.add(t);
      try {return await diagnose(this.diagnostic??(()=>{}),host,'host_read',async()=>{const client=await t.connect(host,'read');return await fn(client);});}
      finally {await t.close();this.active.delete(t);}
    });
    this.tails.set(host,work);
    try{return await work;}finally{if(this.tails.get(host)===work)this.tails.delete(host);}
  }
  async search(owner,{host,query,project_id,limit=10}) {
    const hosts=host?[host]:this.hosts(owner).hosts.map(h=>h.host);
    // Reject arbitrary caller-supplied hosts before opening any route.
    for(const h of hosts)this.grant(owner,h);
    const results=new Array(hosts.length);let next=0;
    const worker=async()=>{while(next<hosts.length){const i=next++,h=hosts[i];
      try {
        const data=await this.withHost(owner,h,project_id,c=>c.searchThreads({query,limit,...(project_id?{projectId:project_id}:{})}));
        const {grant}=this.grant(owner,h,project_id);
        if(!Array.isArray(data.matches))throw failure('source_unavailable');
        const matches=data.matches.filter(m=>typeof m.threadId==='string'&&typeof m.projectId==='string'
          &&(!grant.projectIds||grant.projectIds.includes(m.projectId))&&(!project_id||m.projectId===project_id)).slice(0,limit)
          .map(m=>({...fields(m,['threadId','projectId','source','messageCreatedAt']),snippet:scrub(m.snippet).slice(0,1000)}));
        results[i]={host:h,available:true,matches,exhaustive:false};
        this.audit('fleet.search',`${owner}:${h}`,'returned');
      }catch(error){const reason=reasonFor(error);results[i]={host:h,available:false,reason,matches:[],exhaustive:false};this.audit('fleet.search',`${owner}:${h}`,reason);}
    }};
    await Promise.all([worker(),worker()]);
    // Another host may have taken time while a completed host's scope changed.
    for(const result of results.filter(r=>r.available)) {
      const {grant}=this.grant(owner,result.host,project_id);
      result.matches=result.matches.filter(m=>!grant.projectIds||grant.projectIds.includes(m.projectId));
    }
    return {results,exhaustive:false,coverage:'Native search covers bounded active-thread matches; no pagination or absence guarantee. Read known thread IDs directly, including archived threads.'};
  }
  async read(owner,p) {
    const {host,thread_id,view='messages'}=p;
    let attempts=0,recoveredFrom=null;
    this.audit('fleet.read.cursor',`${owner}:${host}:${thread_id}`,JSON.stringify({view,after_position:p.after_position??null,item_id_hash:p.item_id?createHash('sha256').update(p.item_id).digest('hex'):null,text_offset:p.text_offset??null}));
    try {
      const args={threadId:thread_id,view,limit:25,runLimit:20,maxCharsPerItem:4000,
        ...(p.after_position!==undefined?{afterPosition:p.after_position}:{}),...(p.item_id?{itemId:p.item_id,textOffset:p.text_offset??0}:{})};
      const data=await this.withHost(owner,host,undefined,async c=>{
        for(;;){
          this.grant(owner,host);attempts++;
          try{return await c.readThread({...args});}catch(e){
            const reason=reasonFor(e);
            if(attempts>=2||reason==='source_timeout'||!transientReadReasons.has(reason))throw e;
            recoveredFrom=reason;this.audit('fleet.read.retry',`${owner}:${host}:${thread_id}`,reason);
            await new Promise(resolve=>setTimeout(resolve,250));
          }
        }
      });
      if(!data||typeof data!=='object'||!data.thread)throw failure('source_protocol_error');
      if(data.thread?.threadId!==thread_id)throw failure('identity_mismatch');
      this.grant(owner,host,data.thread.projectId);
      if(!data.thread.projectId)throw failure('identity_mismatch');
      if(!Array.isArray(data.items)||data.items.length>25)throw failure('source_protocol_error');
      if(typeof data.hasMore!=='boolean'||data.nextPosition!=null&&(!Number.isSafeInteger(data.nextPosition)||data.nextPosition<0||p.after_position!==undefined&&data.nextPosition<p.after_position)||data.hasMore&&(data.nextPosition==null||p.after_position!==undefined&&data.nextPosition<=p.after_position))throw failure('invalid_source_pagination');
      for(const item of data.items){
        if(!item||typeof item!=='object'||Array.isArray(item))throw failure('source_protocol_error');
        if(typeof item.text==='string'&&item.text.length>4000)throw failure('source_protocol_error');
        if(item.textTruncated===true&&(!Number.isSafeInteger(item.nextTextOffset)||item.nextTextOffset<=(p.text_offset??0)))throw failure('invalid_source_pagination');
      }
      const local=(data.items??[]).filter(i=>i.sourceThreadId===thread_id);
      const result={host,view,thread:fields(data.thread,['threadId','title','projectId','status','activeRunId','latestRunId','providerInstanceId','model','runtimeMode','pendingRequestCount','runCount','settled','snoozed','snoozedUntil','archived','updatedAt']),
        runs:(data.recentRuns??[]).slice(0,20).map(r=>fields(r,['runId','ordinal','status','requestedAt','startedAt','completedAt'])),
        pullRequests:(data.thread.pullRequests??(data.thread.linkedPullRequest?[data.thread.linkedPullRequest]:[])).slice(0,20).map(pr=>fields(pr,['number','repository','url','state'])),
        items:local.slice(0,25).map(i=>({...fields(i,['itemId','messageId','runId','position','createdBy','type','status','updatedAt','nextTextOffset','textTruncated']),text:scrub(i.text)})),
        hasMore:data.hasMore===true,nextPosition:data.nextPosition??null,excludedInheritedItems:(data.items??[]).length-local.length,
        pagination:'Use after_position=nextPosition while hasMore. For textTruncated items use item_id and text_offset=nextTextOffset until null; offsets refer to the native UTF-16 source, before redaction.',
        runHistoryLimit:20,readback:{attempts,recovered_from:recoveredFrom,requested:{...p,view},consistency:'live_page_not_snapshot'}};
      this.audit('fleet.read',`${owner}:${host}:${thread_id}`,'returned');return result;
    }catch(error){const reason=reasonFor(error);this.audit('fleet.read',`${owner}:${host}`,reason);throw Object.assign(failure(reason),{readRecovery:{...p,view},retryRead:{allowed:transientReadReasons.has(reason)&&attempts<2,max_attempts:2,attempts_used:attempts,reuse_arguments:true}});}
  }
  async close(){this.stopped=true;await Promise.allSettled([...this.tails.values()]);await Promise.allSettled([...this.active].map(t=>t.close()));this.cursorKey.fill(0);}
}

export async function fleetReader(policy,store) {
  const runtimePortCache=new Map();
  const reader=new FleetReader({policy,audit:(...args)=>store.audit(...args),cursorKey:createHmac('sha256',store.key).update('eddie-t3:inventory-cursor:v1').digest(),transport:route=>new T3FleetTransport({
    diagnostic:event=>store.diagnostic(event),
    runtimePortCache,
    ...(route.localClient?localClientOptions(route.localClient,Date.now,'read',route.name):{}),
    fetchImpl:(url,opts)=>fetch(url,{...opts,signal:AbortSignal.timeout(15000)}),
  })});
  reader.diagnostic=event=>store.diagnostic(event);
  return reader;
}
