// SPDX-License-Identifier: AGPL-3.0-or-later
import {createHash} from 'node:crypto';
import {subscriptionActive,subscriptionExpiry} from './subscription-state.mjs';
import {readReason} from './read-errors.mjs';

const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const fail=()=>Object.assign(Error('forbidden'),{reason:'forbidden'});
const terminal=new Set(['completed','failed','cancelled','interrupted']);

// One native MCP subscription, existing encrypted delivery store and read routes.
// Inventory progresses in bounded pages; no task dispatch or per-thread enrollment.
export class FleetEvents {
  constructor(bridge){this.bridge=bridge;}
  hosts(owner){
    const b=this.bridge,p=b.policy().principals.find(p=>p.id===owner&&p.enabled!==false);
    if(!p||!b.fleetReads||!b.commands||p.eddieCaller||p.eddieHostCaller)throw fail();
    return (p.readHosts??[]).map(g=>g.host).filter(host=>{
      try{b.commands.grant(owner,host);return true;}catch{return false;}
    });
  }
  grant(owner,host,projectId,provider){
    if(!this.hosts(owner).includes(host))throw fail();
    const {grant}=this.bridge.commands.grant(owner,host,projectId);
    if(provider!==undefined&&!grant.providerInstanceIds.includes(provider))throw fail();
    return grant;
  }
  active(owner){return this.bridge.store.all('subscription').filter(s=>s.name==='t3.fleet.activity'&&(!owner||s.owner===owner)&&subscriptionActive(s,this.bridge.now()));}
  enqueue(sub,data,identity,timestamp=new Date(this.bridge.now()).toISOString()){
    const b=this.bridge,eventId='evt_'+hash(['t3.fleet.activity',sub.id,identity]);
    const id=sub.id+':'+eventId,event={eventId,name:'t3.fleet.activity',timestamp,data,cursor:null};
    if(b.store.insert('delivery',id,{id,subId:sub.id,event,attempts:0,nextAt:b.now(),status:'pending'}))b.store.audit('fleet.event',eventId,data.kind);
  }
  status(owner){
    const b=this.bridge,hosts=this.hosts(owner),subs=this.active(owner);
    const readable=b.policy().principals.find(p=>p.id===owner&&p.enabled!==false)?.readHosts??[];
    return {subscriptions:subs.map(s=>({subscription_id:s.id,expires_at:subscriptionExpiry(s),hosts:hosts.map(host=>{
      const record=b.store.get('fleet_scan',hash([s.id,host]));
      return {host,state:record?.state??'not_checked',observed_at:record?.at??null,last_complete_at:record?.lastCompleteAt??null,
        scanning:!!record?.cursor,reason:record?.reason??null,last_complete_age_ms:record?.lastCompleteAt?Math.max(0,b.now()-Date.parse(record.lastCompleteAt)):null,
        monitoring_requires_live_command_grant:true,command_grant_expires_at:Number.isFinite(b.commands.grant(owner,host).grant.expiresAt)?new Date(b.commands.grant(owner,host).grant.expiresAt).toISOString():null};
    })})),excluded_hosts:readable.filter(g=>!hosts.includes(g.host)).map(g=>({host:g.host,reason:'live_command_scope_unavailable'})),
      execution_authority_changed:false,delivery_acknowledgement_is_agent_execution:false,
      consistency:'Live paginated observation, not an atomic snapshot. Coverage is incomplete until every host completes a scan. Native reads retain 20 recent runs; outages or bursts beyond that window can miss completions. Questions are delivered only while pending. No historical replay guarantee.'};
  }
  coverage(sub,host,state,previous,extra={}){
    const b=this.bridge,id=hash([sub.id,host]),at=new Date(b.now()).toISOString();
    const next={...previous,...extra,id,subId:sub.id,host,state,at};
    b.store.transaction(()=>{
      if(previous?.state!==state){
        next.revision=(previous?.revision??0)+1;
        this.enqueue(sub,{host,kind:'coverage_changed',state,reason:next.reason??null},['coverage',host,next.revision]);
        b.store.audit('fleet.coverage',id,state);
      }
      b.store.put('fleet_scan',id,next);
    });
  }
  async observeThread(sub,host,t){
    const b=this.bridge;
    this.grant(sub.owner,host,t.projectId,t.providerInstanceId);
    const key=hash([sub.id,host,t.threadId]),prior=b.store.get('fleet_thread',key);
    const fingerprint=hash([t.updatedAt,t.latestRunId,t.status,t.providerInstanceId,t.projectId]);
    if(prior?.fingerprint===fingerprint&&!prior.pending&&!['running','waiting','starting','queued','preparing'].includes(t.status))return;
    // Do not walk old terminal conversations just to rediscover bootstrap history.
    if(!prior&&terminal.has(t.status)&&Date.parse(t.updatedAt)<Date.parse(sub.observeAfter)){
      b.store.put('fleet_thread',key,{fingerprint,pending:false});return;
    }
    const data=await b.fleetReads.read(sub.owner,{host,thread_id:t.threadId});
    if(data.thread.projectId!==t.projectId||data.thread.providerInstanceId!==t.providerInstanceId)throw Object.assign(Error('identity_mismatch'),{reason:'identity_mismatch'});
    this.grant(sub.owner,host,t.projectId,data.thread.providerInstanceId);
    if(!subscriptionActive(b.store.get('subscription',sub.id),b.now()))throw fail();
    const base={host,thread_id:t.threadId,project_id:t.projectId,provider_instance_id:t.providerInstanceId};
    for(const run of data.runs??[]){
      if(!terminal.has(run.status)||!run.runId||!Number.isFinite(Date.parse(run.completedAt))||Date.parse(run.completedAt)<Date.parse(sub.observeAfter))continue;
      this.enqueue(sub,{...base,kind:'task_finished',run_id:run.runId,status:run.status},[host,t.threadId,'run',run.runId],run.completedAt);
    }
    let cursor;
    if(data.thread.pendingRequestCount>0)do{
      const page=await b.commands.requests(sub.owner,{host,thread_id:t.threadId,...(cursor?{after_request_id:cursor}:{})},{forLane:true});
      if(page.project_id!==t.projectId)throw Object.assign(Error('identity_mismatch'),{reason:'identity_mismatch'});
      this.grant(sub.owner,host,t.projectId,t.providerInstanceId);
      if(!subscriptionActive(b.store.get('subscription',sub.id),b.now()))throw fail();
      for(const r of page.requests){
        if(r.run_id)this.enqueue(sub,{...base,kind:'input_requested',run_id:r.run_id,native_request_id:r.native_request_id,live_answer_allowed:r.live_answer_allowed},[host,t.threadId,'question',r.native_request_id]);
      }
      if(page.next_cursor!==null&&page.next_cursor!==undefined&&(!page.next_cursor||cursor&&page.next_cursor<=cursor))throw Error('source_unavailable');
      cursor=page.next_cursor;
    }while(cursor);
    b.store.put('fleet_thread',key,{fingerprint,pending:data.thread.pendingRequestCount>0});
  }
  async host(sub,host){
    const b=this.bridge,id=hash([sub.id,host]),previous=b.store.get('fleet_scan',id);
    try{
      this.grant(sub.owner,host);
      const page=await b.fleetReads.inventory(sub.owner,{host,cursor:previous?.cursor??undefined});
      if(!Array.isArray(page.threads)||page.next_cursor!==null&&(typeof page.next_cursor!=='string'||!page.next_cursor||page.next_cursor===previous?.cursor))throw Error('source_unavailable');
      let failed=false;
      for(const t of page.threads){
        if(typeof t.providerInstanceId!=='string'||!t.providerInstanceId){failed=true;continue;}
        try{this.grant(sub.owner,host,t.projectId,t.providerInstanceId);}catch{continue;}
        try{await this.observeThread(sub,host,t);}catch{failed=true;}
      }
      this.grant(sub.owner,host);
      if(!subscriptionActive(b.store.get('subscription',sub.id),b.now()))return;
      // Failed reads retain the page checkpoint; duplicate observations are idempotent.
      this.coverage(sub,host,failed?'degraded':page.next_cursor&&(!previous?.lastCompleteAt||['unavailable','degraded','scanning'].includes(previous?.state))?'scanning':'available',previous,
        {cursor:failed?previous?.cursor??null:page.next_cursor,reason:failed?'thread_read_unavailable':null,
          ...(!failed&&!page.next_cursor?{lastCompleteAt:new Date(b.now()).toISOString()}: {})});
    }catch(e){
      if(!subscriptionActive(b.store.get('subscription',sub.id),b.now()))return;
      try{this.grant(sub.owner,host);}catch{return;}
      const restart=['invalid_inventory_cursor','inventory_changed'].includes(e.reason);
      this.coverage(sub,host,'unavailable',previous,{reason:restart?'inventory_restarted':readReason(e),...(restart?{cursor:null}:{})});
    }
  }
  async observe(){
    for(const sub of this.active()){
      let hosts;try{hosts=this.hosts(sub.owner);}catch{continue;}
      // Host failure cannot block another host's scan. Reads remain serialized by FleetReader.
      await Promise.all(hosts.map(host=>this.host(sub,host)));
    }
  }
  async deliverable(sub,event){
    const b=this.bridge,d=event.data;
    this.grant(sub.owner,d.host,d.project_id,d.provider_instance_id);
    if(d.kind!=='coverage_changed'){
      const data=await b.fleetReads.read(sub.owner,{host:d.host,thread_id:d.thread_id});
      if(data.thread.projectId!==d.project_id||data.thread.providerInstanceId!==d.provider_instance_id)throw fail();
      this.grant(sub.owner,d.host,d.project_id,d.provider_instance_id);
      if(d.kind==='input_requested'){
        const page=await b.commands.requests(sub.owner,{host:d.host,thread_id:d.thread_id,native_request_id:d.native_request_id},{forLane:true});
        if(page.project_id!==d.project_id||!page.requests.some(r=>r.run_id===d.run_id&&r.native_request_id===d.native_request_id))throw Object.assign(Error('input_request_not_pending'),{reason:'input_request_not_pending'});
        this.grant(sub.owner,d.host,d.project_id,d.provider_instance_id);
      }
    }
  }
}
