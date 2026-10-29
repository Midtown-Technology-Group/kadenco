// SPDX-License-Identifier: AGPL-3.0-or-later
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {localSource} from '../src/local-source.mjs';
import {configSchema} from '../src/config.mjs';

test('native projection lifecycle and messages are read with a strict thread boundary',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'t3-source-')),path=join(dir,'source.db'),db=new DatabaseSync(path);
  db.exec(`CREATE TABLE orchestration_v2_projection_threads(thread_id TEXT, deleted_at TEXT, payload_json TEXT);
  CREATE TABLE orchestration_v2_projection_runs(thread_id TEXT, ordinal INTEGER, payload_json TEXT);
  CREATE TABLE orchestration_v2_projection_messages(thread_id TEXT, run_id TEXT, created_at TEXT, message_id TEXT, payload_json TEXT);`);
  db.prepare('INSERT INTO orchestration_v2_projection_threads VALUES(?,NULL,?)').run('t',JSON.stringify({id:'t',providerInstanceId:'opencode',modelSelection:{model:'test'},runtimeMode:'approval-required'}));
  db.prepare('INSERT INTO orchestration_v2_projection_runs VALUES(?,1,?)').run('t',JSON.stringify({id:'r',threadId:'t',status:'completed',completedAt:'2026-10-18T15:00:00Z'}));
  const add=db.prepare('INSERT INTO orchestration_v2_projection_messages VALUES(?,?,?,?,?)');
  for(let i=0;i<27;i++)add.run('t','r',String(i).padStart(2,'0'),'m'+i,JSON.stringify({id:'m'+i,threadId:'t',runId:'r',text:'result '+i,role:'assistant'}));
  db.close();const source=localSource(path);
  t.after(()=>{source.close();rmSync(dir,{recursive:true,force:true});});
  const a=await source.read({host:'local',threadId:'t'});
  assert.equal(a.thread.latestRunId,'r');assert.equal(a.items.length,25);assert.equal(a.hasMore,true);
  const b=await source.read({host:'local',threadId:'t'},false,{afterPosition:a.nextPosition});
  assert.equal(b.items.length,2);assert.equal(b.hasMore,false);
  assert.equal((await source.read({host:'local',threadId:'t'},false,{runId:'other'})).items.length,0);
  await assert.rejects(source.read({host:'local',threadId:'missing'}),/not_found/);
  await assert.rejects(source.read({host:'remote',threadId:'t'}),/local_host_required/);
  await assert.rejects(source.followup(),/read_only/);
});

test('invalid enrollment, Codex grants and local-source write grants fail config validation',()=>{
  const p={stateDirectory:'.',source:{type:'local-projection',databasePath:'db'},callbackHosts:[],principals:[],sessions:[]};
  assert.ok(configSchema.safeParse(p).success);
  const s={id:'a',host:'local',threadId:'t',observeAfter:'bad'};
  assert.equal(configSchema.safeParse({...p,sessions:[s]}).success,false);
  s.observeAfter='2026-10-18T00:00:00Z';s.followup={action:'verify_result',expiresAt:Date.now()+1000,providerInstanceId:'codex',model:'x'};
  assert.equal(configSchema.safeParse({...p,sessions:[s]}).success,false);
  s.followup.providerInstanceId='opencode';assert.equal(configSchema.safeParse({...p,sessions:[s]}).success,false);
});
