// SPDX-License-Identifier: AGPL-3.0-or-later
// Virtual identities preserve the existing per-thread exchange ownership without
// creating credentials or policy entries for each thread. Only an explicitly
// enrolled passive host principal can produce one; it has no execution tools.
const prefix='host-caller:';
export function hostCallerOwner(owner,threadId){
  return prefix+Buffer.from(JSON.stringify([owner,threadId])).toString('base64url');
}
export function resolveHostCaller(policy,owner,now){
  try{
    if(!owner.startsWith(prefix)||owner.length>6000)return null;
    const [parent,threadId]=JSON.parse(Buffer.from(owner.slice(prefix.length),'base64url').toString());
    if(typeof parent!=='string'||typeof threadId!=='string'||!threadId||threadId.length>2048||hostCallerOwner(parent,threadId)!==owner)return null;
    const principal=policy.principals.find(p=>p.id===parent&&p.enabled!==false),g=principal?.eddieHostCaller;
    if(!g||g.expiresAt<=now)return null;
    return {id:owner,enabled:true,eddieCaller:{...g,threadId}};
  }catch{return null;}
}
