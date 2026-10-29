// SPDX-License-Identifier: AGPL-3.0-or-later
import { z } from 'zod';

const session=z.object({id:z.string().min(1).max(100),host:z.string().min(1),threadId:z.string().min(1).max(2048),observeAfter:z.iso.datetime(),
  followup:z.object({action:z.literal('verify_result'),dedicated:z.literal(true),maxPerDay:z.number().int().min(1).max(5).default(1),expiresAt:z.number().int().positive(),providerInstanceId:z.literal('opencode'),model:z.string().min(1)}).strict().optional()}).strict();
const hostName=z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/);
const localClient=z.object({origin:z.string().url(),tokenFile:z.string().min(1)}).strict();
const readGrant=z.object({host:hostName,projectIds:z.array(z.string().min(1).max(2048)).min(1).max(100).optional()}).strict();
const creationRuntime=z.object({allowedModes:z.array(z.enum(['approval-required','full-access'])).min(1).max(2),defaultMode:z.enum(['approval-required','full-access']),authorization:z.string().min(1).max(500)}).strict().refine(g=>new Set(g.allowedModes).size===g.allowedModes.length&&g.allowedModes.includes(g.defaultMode),'invalid creation runtime grant');
// null explicitly removes the command-count cap; omitted host limits retain
// their old default. Authorization, expiry and exact target checks still apply.
const codexException=z.object({threadId:z.string().uuid(),projectId:z.string().min(1).max(2048),providerInstanceId:hostName,model:z.string().min(1).max(200),expiresAt:z.number().int().positive(),maxPerDay:z.number().int().min(1).max(10).nullable(),authorization:z.string().min(1).max(500)}).strict();
export const configSchema=z.object({
  port:z.number().int().min(1024).max(65535).default(41880),pollMs:z.number().int().min(5000).max(60000).default(10000),
  stateDirectory:z.string().min(1),fleetHelperPath:z.string().optional(),
  source:z.object({type:z.literal('local-projection'),databasePath:z.string().min(1)}).strict().optional(),
  localClient:localClient.optional(),
  fleetRead:z.object({hosts:z.array(z.object({name:hostName,localClient:localClient.optional()}).strict()).min(1).max(20)}).strict().optional(),
  nativeDelivery:z.object({hosts:z.array(z.object({name:hostName,command:z.string().min(1).max(2048),args:z.array(z.string().max(2048)).max(20).optional(),baseDirectory:z.string().min(1).max(2048).optional(),electron:z.boolean().optional(),ssh:hostName.optional()}).strict()).min(1).max(20)}).strict().optional(),
  callbackHosts:z.array(z.string().regex(/^[a-z0-9.-]+$/)).max(10),
  collaboration:z.object({enabled:z.boolean().default(false),port:z.number().int().min(1024).max(65535).default(41882),
    origin:z.string().url().refine(s=>{const u=new URL(s);return u.protocol==='https:'&&u.origin===s;}),
    issuer:z.string().regex(/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/),audience:z.string().min(1).max(200),identityProviderId:z.string().uuid(),
    brokerPrincipal:z.string().min(1).max(100),ownerSubjects:z.array(z.string().min(1).max(200)).min(1).max(20)}).strict().optional(),
  principals:z.array(z.object({id:z.string().min(1).max(100).refine(id=>!id.startsWith('host-caller:')),tokenSha256:z.string().regex(/^[a-f0-9]{64}$/),enabled:z.boolean().optional(),sessions:z.array(z.string()),readHosts:z.array(readGrant).max(20).optional(),
    commandHosts:z.array(z.object({host:hostName,projectIds:z.array(z.string().min(1).max(2048)).min(1).max(100).optional(),providerInstanceIds:z.array(hostName).min(1).max(20),expiresAt:z.number().int().positive(),maxPerDay:z.number().int().min(1).max(100).nullable().default(10),creationRuntime:creationRuntime.optional(),codexExceptions:z.array(codexException).max(20).optional()}).strict()).max(20).optional(),
    eddieHostCaller:z.object({host:hostName,reviewer:z.string().min(1).max(100),expiresAt:z.number().int().positive(),maxPerDay:z.number().int().min(1).max(100).default(10)}).strict().optional(),
    eddieInbox:z.literal(true).optional(),eddieCaller:z.object({host:hostName,threadId:z.string().min(1).max(2048),reviewer:z.string().min(1).max(100),expiresAt:z.number().int().positive(),maxPerDay:z.number().int().min(1).max(100).default(10)}).strict().optional()}).strict()).max(2000),
  sessions:z.array(session).max(50),
}).strict().superRefine((p,ctx)=>{
  if(!p.source&&!p.fleetHelperPath)ctx.addIssue({code:'custom',message:'source or fleetHelperPath required'});
  if(new Set(p.sessions.map(s=>s.id)).size!==p.sessions.length)ctx.addIssue({code:'custom',message:'duplicate session'});
  if(new Set(p.principals.map(s=>s.id)).size!==p.principals.length)ctx.addIssue({code:'custom',message:'duplicate principal'});
  if(new Set(p.principals.map(s=>s.tokenSha256)).size!==p.principals.length)ctx.addIssue({code:'custom',message:'duplicate credential'});
  if(p.source && p.sessions.some(s=>s.followup&&(s.host!=='local'||!p.localClient)))ctx.addIssue({code:'custom',message:'local projection writes require an explicitly enrolled existing local MCP client'});
  if(p.source && p.sessions.some(s=>s.host!=='local'&&!p.fleetRead?.hosts.some(h=>h.name===s.host)))ctx.addIssue({code:'custom',message:'remote sessions require an enrolled fleet read route'});
  if(p.localClient&&(!p.source||!p.fleetHelperPath))ctx.addIssue({code:'custom',message:'local MCP client requires local source and fleet helper'});
  const hosts=p.fleetRead?.hosts.map(h=>h.name)??[];
  if(p.collaboration){const c=p.collaboration,broker=p.principals.find(x=>x.id===c.brokerPrincipal&&x.enabled!==false);
    if(c.port===p.port||!p.fleetRead||!p.nativeDelivery||!broker?.commandHosts?.length||broker.eddieCaller||broker.eddieHostCaller||new Set(c.ownerSubjects).size!==c.ownerSubjects.length)ctx.addIssue({code:'custom',message:'invalid collaboration broker, owner or listener'});
  }
  if(new Set(hosts).size!==hosts.length)ctx.addIssue({code:'custom',message:'duplicate fleet host'});
  const writeHosts=p.nativeDelivery?.hosts.map(h=>h.name)??[];
  if(new Set(writeHosts).size!==writeHosts.length||writeHosts.some(h=>!hosts.includes(h)))ctx.addIssue({code:'custom',message:'ambiguous or unreadable native commands route'});
  for(const principal of p.principals) {
    const grants=principal.readHosts??[];
    if(p.source&&p.sessions.some(s=>s.host!=='local'&&principal.sessions.includes(s.id)&&!grants.some(g=>g.host===s.host)))
      ctx.addIssue({code:'custom',message:'remote session requires a fleet read grant'});
    if(new Set(grants.map(g=>g.host)).size!==grants.length||grants.some(g=>!hosts.includes(g.host)))
      ctx.addIssue({code:'custom',message:'ambiguous or unenrolled fleet read grant'});
    if(principal.eddieInbox&&!p.fleetRead)ctx.addIssue({code:'custom',message:'inbox requires fleet reads'});
    const commands=principal.commandHosts??[];
    if(new Set(commands.map(g=>g.host)).size!==commands.length||commands.some(g=>!writeHosts.includes(g.host)||!grants.some(r=>r.host===g.host)))ctx.addIssue({code:'custom',message:'invalid commands grant'});
    for(const g of commands){
      const exceptions=g.codexExceptions??[],read=grants.find(r=>r.host===g.host);
      if(new Set(exceptions.map(e=>e.threadId)).size!==exceptions.length||exceptions.some(e=>e.expiresAt>g.expiresAt||g.maxPerDay!==null&&(e.maxPerDay===null||e.maxPerDay>g.maxPerDay)||g.projectIds&&!g.projectIds.includes(e.projectId)||read?.projectIds&&!read.projectIds.includes(e.projectId)))
        ctx.addIssue({code:'custom',message:'invalid exact-thread Codex exception'});
    }
    if(principal.eddieCaller||principal.eddieHostCaller){
      const g=principal.eddieCaller??principal.eddieHostCaller,reviewer=p.principals.find(x=>x.id===g.reviewer);
      if(principal.eddieCaller&&principal.eddieHostCaller||principal.eddieInbox||principal.sessions.length||grants.length||commands.length||!reviewer?.eddieInbox||!reviewer.readHosts?.some(h=>h.host===g.host))
        ctx.addIssue({code:'custom',message:'caller must be separate and target an authorized inbox read host'});
    }
  }
});
