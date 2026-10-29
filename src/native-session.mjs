// SPDX-License-Identifier: AGPL-3.0-or-later
// Private broker for the existing native orchestration RPC. Never reuse an MCP
// client bearer on /ws: it is a different native authorization audience.
import {execFile as execFileCb} from 'node:child_process';
import {promisify} from 'node:util';
const execFile=promisify(execFileCb);
const fail=reason=>Object.assign(new Error(reason),{reason});
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";

export async function nativeSession(route,fn,{execute=execFile,fetchImpl=fetch,Socket=WebSocket}={}) {
  const run=async args=>{
    try {
      const opts={encoding:'utf8',timeout:15000,maxBuffer:65536,windowsHide:true,
        env:{...process.env,...(route.electron?{ELECTRON_RUN_AS_NODE:'1'}:{})}};
      const argv=[...(route.args??[]),'auth','session',...args,...(route.baseDirectory?['--base-dir',route.baseDirectory]:[])];
      return await execute(route.command,route.ssh
        ?['-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8',route.ssh,argv.map(quote).join(' ')]
        :argv,opts);
    }catch{throw fail('native_auth_unavailable');}
  };
  let issued;
  try {
    const result=await run(['issue','--scope','orchestration:read',...(route.readOnly?[]:['--scope','orchestration:operate']),'--ttl','2m','--subject','eddie-t3-delivery','--label','Eddie T3 private delivery','--json']);
    issued=JSON.parse(result.stdout);
    if(!issued.sessionId||!issued.token||issued.subject!=='eddie-t3-delivery')throw fail('native_auth_unavailable');
    const call=async(base,tag,payload)=>{
      if(!['server.getConfig','orchestration.getThreadProjection','orchestration.dispatchCommand'].includes(tag))throw fail('forbidden');
      if(route.readOnly&&tag==='orchestration.dispatchCommand')throw fail('forbidden');
      const origin=new URL(base);
      if(origin.protocol!=='http:'||origin.hostname!=='127.0.0.1'||origin.pathname!=='/'||origin.username||origin.password||origin.search||origin.hash)throw fail('forbidden');
      let response;
      try{response=await fetchImpl(new URL('/api/auth/websocket-ticket',origin),{method:'POST',headers:{authorization:'Bearer '+issued.token},redirect:'error',signal:AbortSignal.timeout(10000)});}
      catch{throw fail('native_auth_unavailable');}
      if(!response.ok)throw fail('native_auth_unavailable');
      const ticket=await response.json();
      if(typeof ticket.ticket!=='string'||!ticket.ticket)throw fail('native_auth_unavailable');
      const url=new URL('/ws',origin);url.protocol='ws:';url.searchParams.set('wsTicket',ticket.ticket);url.searchParams.set('orchestrationProtocol','2');
      return new Promise((resolve,reject)=>{
        let socket,done=false;
        const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);socket?.close();error?reject(error):resolve(value);};
        const timer=setTimeout(()=>finish(fail('native_outcome_unknown')),15000);
        try{socket=new Socket(url);}catch{return finish(fail('native_auth_unavailable'));}
        socket.addEventListener('open',()=>{
          if(done)return;
          try{if(tag==='orchestration.dispatchCommand')route.authorizeDispatch?.();socket.send(JSON.stringify({_tag:'Request',id:'1',tag,payload,headers:[]}));}
          catch(e){finish(e?.reason?e:fail('forbidden'));}
        });
        socket.addEventListener('message',event=>{
          try {
            const messages=JSON.parse(String(event.data));
            for(const m of Array.isArray(messages)?messages:[messages]){
              if(m._tag==='Ping'){socket.send(JSON.stringify({_tag:'Pong'}));continue;}
              if(m._tag!=='Exit'||String(m.requestId)!=='1')continue;
              if(m.exit?._tag==='Success')finish(null,m.exit.value);
              else finish(fail('native_rejected'));
            }
          }catch{finish(fail('native_outcome_unknown'));}
        });
        socket.addEventListener('error',()=>finish(fail('native_outcome_unknown')));
        socket.addEventListener('close',()=>finish(fail('native_outcome_unknown')));
      });
    };
    return await fn(call);
  } finally {
    // Lost issuance/revocation responses still leave a two-minute expiry.
    if(issued?.sessionId){try{await run(['revoke',issued.sessionId]);}catch{route.audit?.('command.auth',route.name,'revoke_failed_expires_2m');}}
    issued=null;
  }
}
