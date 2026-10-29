// SPDX-License-Identifier: AGPL-3.0-or-later
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {randomBytes} from 'node:crypto';

test('standalone local-projection entrypoint starts with synthetic state and no private helper or fleet credentials',async()=>{
 const directory=mkdtempSync(join(tmpdir(),'public-relay-startup-')),state=join(directory,'state');mkdirSync(state,{mode:0o700});
 const database=join(directory,'synthetic.db'),db=new DatabaseSync(database);
 db.exec(`CREATE TABLE orchestration_v2_projection_threads(thread_id TEXT,deleted_at TEXT,payload_json TEXT);
 CREATE TABLE orchestration_v2_projection_runs(thread_id TEXT,ordinal INTEGER,payload_json TEXT);
 CREATE TABLE orchestration_v2_projection_messages(thread_id TEXT,run_id TEXT,created_at TEXT,message_id TEXT,payload_json TEXT);`);db.close();
 const listener=createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));
 const policy=join(directory,'config.json');writeFileSync(policy,JSON.stringify({port,stateDirectory:state,source:{type:'local-projection',databasePath:database},callbackHosts:[],principals:[],sessions:[]}));
 const child=spawn(process.execPath,['src/main.mjs'],{env:{...process.env,EDDIE_T3_CONFIG:policy,EDDIE_T3_STATE_KEY:randomBytes(32).toString('base64')},stdio:['ignore','ignore','pipe'],windowsHide:true});
 const exited=once(child,'exit');let stderr='';child.stderr.on('data',b=>{stderr+=b;});
 try{
  let ready=false;const deadline=Date.now()+10000;
  while(Date.now()<deadline&&child.exitCode===null){
   try{const response=await fetch(`http://127.0.0.1:${port}/healthz`,{signal:AbortSignal.timeout(500)});if(response.ok){ready=true;break;}}catch{}
   await new Promise(r=>setTimeout(r,50));
  }
  assert.equal(ready,true,stderr);assert.equal(stderr.includes('listening on loopback'),true);
 }finally{if(child.exitCode===null)child.kill('SIGTERM');await exited;rmSync(directory,{recursive:true,force:true});}
});
