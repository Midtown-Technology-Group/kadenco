// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, statSync } from 'node:fs';
import { Store } from './store.mjs';
import { Bridge } from './bridge.mjs';
import { fleetBackend } from './backend.mjs';
import { postWebhook } from './webhook.mjs';
import { httpServer } from './server.mjs';
import { localSource } from './local-source.mjs';
import { configSchema } from './config.mjs';
import { withLocalFollowup } from './local-client.mjs';
import { fleetReader } from './fleet-read.mjs';
import { Commands } from './commands.mjs';
import { withFleetSessions } from './fleet-source.mjs';
import {collaborationServer} from './collaboration-http.mjs';
import {diagnosticContext,diagnose} from './diagnostics.mjs';

const configPath=process.env.EDDIE_T3_CONFIG;
if(!configPath || !process.env.EDDIE_T3_STATE_KEY) throw new Error('EDDIE_T3_CONFIG and EDDIE_T3_STATE_KEY required');
const policy=()=>configSchema.parse(JSON.parse(readFileSync(configPath,'utf8')));
const config=policy();
const key=Buffer.from(process.env.EDDIE_T3_STATE_KEY,'base64');
delete process.env.EDDIE_T3_STATE_KEY;
// The parent state directory must already have an owner-only ACL. Refuse
// permissive POSIX state instead of silently weakening persistent secret storage.
if(process.platform!=='win32' && (statSync(config.stateDirectory).mode & 0o077)) throw new Error('state_directory_must_be_private');
const store=new Store(config.stateDirectory+'/bridge.db',key);
if(!config.source||config.localClient||config.fleetHelperPath)throw Error('Public profile requires local-projection source; private helper profiles are not bundled');
let backend=localSource(config.source.databasePath);
const reader=config.fleetRead?await fleetReader(policy,store):null;
if(config.source)backend=withFleetSessions(backend,reader,policy);
const bridge=new Bridge({store,backend,policy,post:(url,headers,body)=>postWebhook(url,headers,body,policy().callbackHosts)});
if(reader)bridge.fleetReads=reader;
if(config.nativeDelivery)bridge.commands=new Commands({policy,store,reader:bridge.fleetReads});
const server=httpServer(bridge);
await new Promise(resolve=>server.listen(config.port??41880,'127.0.0.1',resolve));
const collaboration=config.collaboration?.enabled?collaborationServer(bridge):null;
if(collaboration)await new Promise((resolve,reject)=>{collaboration.once('error',reject);collaboration.listen(config.collaboration.port,'127.0.0.1',resolve);});
let stopped=false;
let inFlight=Promise.resolve();
async function cycle(){
  if(stopped)return;
  try{await diagnosticContext('worker','event_cycle',async()=>{await diagnose(e=>store.diagnostic(e),'relay','worker',()=>bridge.observe());await bridge.deliver();await bridge.fleetEvents.observe();await bridge.deliver();});}catch{store.audit('worker.cycle','bridge','failed');}
  if(!stopped)setTimeout(()=>{inFlight=cycle();},Math.max(5000,config.pollMs??10000));
}
inFlight=cycle();
async function shutdown(){stopped=true;collaboration?.stopStreams();await Promise.all([server,collaboration].filter(Boolean).map(s=>new Promise(resolve=>s.close(resolve))));await inFlight;await bridge.fleetReads?.close();await backend.close();store.close();process.exit(0);}
process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);
console.error('Kadenco 0.1.0-alpha.1 listening on loopback; no model calls in event worker');
