// SPDX-License-Identifier: AGPL-3.0-or-later
// Operator-owned acceptance against the deployed MCP, not a second dispatcher.
// Bearer is supplied privately by the existing credential launcher, never saved.
import {readFileSync,writeFileSync,existsSync,renameSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
const [mode,proofFile,projectId]=process.argv.slice(2);
if(!['prepare','create','read'].includes(mode)||!proofFile)throw Error('Use prepare|create|read proof-file [existing-local-project-id]');
if(mode==='prepare'){
  if(!projectId)throw Error('Explicit existing local project required');
  const input={host:'local',project_id:projectId,title:'Eddie native creation canary',provider_instance_id:'codex',model:'gpt-6.1-sol',
    options:[{id:'reasoningEffort',value:'medium'},{id:'serviceTier',value:'default'}],runtime_mode:'approval-required',request_id:randomUUID(),execution:'allow_new_thread',
    message:'the owner authorized this single harmless connector acceptance turn. Do not use tools, run commands, edit files, delegate or contact anyone. Reply exactly EDDIE_T3_CREATE_OK and stop.'};
  writeFileSync(proofFile,JSON.stringify({input,prepared_at:new Date().toISOString()},null,2),{flag:'wx',mode:0o600,flush:true});
  console.log(JSON.stringify({prepared:true,request_id:input.request_id}));
}else{
  const proof=JSON.parse(readFileSync(proofFile,'utf8')),authorization=process.env.EDDIE_T3_MCP_AUTH;delete process.env.EDDIE_T3_MCP_AUTH;
  if(!authorization?.startsWith('Bearer '))throw Error('Existing private MCP bearer required');
  const client=new Client({name:'eddie-creation-acceptance',version:'0.10.5'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
  try{
    const port=Number(process.env.EDDIE_T3_ACCEPTANCE_PORT??41880);if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Invalid loopback acceptance port');
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`),{requestInit:{headers:{Authorization:authorization}}}));
    proof.tools=(await client.listTools()).tools.map(t=>t.name);if(!proof.tools.includes('create_thread')||!proof.tools.includes('get_thread_creation_options'))throw Error('Deployed creation tools unavailable');
    const invoke=async(name,args)=>{const r=await client.callTool({name,arguments:args});if(r.isError)throw Error(r.structuredContent?.reason??'MCP refused');return r.structuredContent;};
    // Persist the one-shot attempt marker BEFORE the mutation. Any restart or
    // uncertainty can only read the original receipt, even when it is absent.
    if(mode==='create'&&!existsSync(proofFile+'.attempted')){
      writeFileSync(proofFile+'.attempted',JSON.stringify({input:proof.input,attempted_at:new Date().toISOString()}),{flag:'wx',mode:0o600,flush:true});
      proof.submitted=await invoke('create_thread',proof.input);
    }
    proof.receipt=await invoke('get_delivery_receipt',{request_id:proof.input.request_id});proof.observed_at=new Date().toISOString();
    // The immutable request file is never truncated or replaced. A failed
    // observation write cannot destroy the UUID needed for reconciliation.
    const observation=proofFile+'.observation.json',temp=observation+'.'+randomUUID();
    writeFileSync(temp,JSON.stringify(proof,null,2),{flag:'wx',mode:0o600,flush:true});renameSync(temp,observation);
    const r=proof.receipt,p=proof.input,options=x=>JSON.stringify([...(x??[])].sort((a,b)=>a.id.localeCompare(b.id)));
    const passed=r.request_id===p.request_id&&r.host===p.host&&r.project_id===p.project_id&&r.stored===true&&r.thread_observed===true&&typeof r.thread_id==='string'&&!!r.thread_id
      &&r.create_submission==='accepted'&&r.start_submission==='accepted'&&r.run_bound===true&&typeof r.run_id==='string'&&!!r.run_id&&r.run_status==='completed'&&r.terminal===true
      &&r.run_status_fresh===true&&r.result_fresh===true&&r.result==='EDDIE_T3_CREATE_OK'&&r.model_selection?.instanceId===p.provider_instance_id&&r.model_selection?.model===p.model&&options(r.model_selection.options)===options(p.options);
    console.log(JSON.stringify({request_id:p.request_id,tools_visible:true,acceptance:passed?'passed':'incomplete',receipt:r}));
    process.exitCode=passed?0:r.terminal?1:2;
  }catch{console.error(JSON.stringify({request_id:proof.input.request_id,acceptance:'incomplete',reason:'Inspect original receipt and safe adapter audit',automatic_resend:false}));process.exitCode=1;}
  finally{await client.close();}
}
