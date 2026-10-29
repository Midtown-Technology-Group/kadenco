// SPDX-License-Identifier: AGPL-3.0-or-later
import { pathToFileURL } from 'node:url';

// Reuse the installed, reviewed fleet helper, without editing its cache or
// exporting its credentials. This adapter never bootstraps authentication.
export async function fleetBackend(helperPath,transportOptions={}) {
  const {T3FleetTransport} = await import(pathToFileURL(helperPath).href);
  const active=new Set();
  const open=()=>{
    const transport=new T3FleetTransport({...transportOptions,fetchImpl:(url,opts)=>fetch(url,{...opts,signal:AbortSignal.timeout(15000)})});
    active.add(transport);return transport;
  };
  const withCurrent=async(session,expectedRunId,fn)=>{
    const transport=open();
    try {
      const client=await transport.connect(session.host,'operate');
      const current=await client.readThread({threadId:session.threadId,limit:1});
      const g=session.followup;
      if(current.thread?.threadId!==session.threadId || current.thread.activeRunId || current.thread.latestRunId!==expectedRunId
        || current.thread.providerInstanceId!==g.providerInstanceId || current.thread.model!==g.model
        || current.thread.runtimeMode!=='approval-required') throw new Error('followup_boundary_changed');
      return await fn(client);
    } finally {await transport.close();active.delete(transport);}
  };
  return {
    supportsFollowup:true,
    async read(session,activity=false,options={}) {
      const transport=open();
      try {
        const client=await transport.connect(session.host,'read');
        const data=await client.readThread({threadId:session.threadId,view:activity?'activity':'messages',limit:25,runLimit:20,maxCharsPerItem:4000,
          ...(options.afterPosition!==undefined?{afterPosition:options.afterPosition}:{})});
        if(options.runId)data.items=data.items.filter(i=>i.runId===options.runId);
        return data;
      } finally {await transport.close();active.delete(transport);}
    },
    preflight:(session,runId)=>withCurrent(session,runId,async()=>{}),
    followup:(session,message,requestId,runId)=>withCurrent(session,runId,client=>
      client.sendThreadMessage({threadId:session.threadId,message,mode:'queue',clientRequestId:requestId})),
    close:()=>Promise.all([...active].map(t=>t.close())),
  };
}
