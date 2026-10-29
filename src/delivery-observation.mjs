// SPDX-License-Identifier: AGPL-3.0-or-later
// Projection evidence only. A cancelled queue slot is not proof that its
// message was undelivered: T3 can move that exact message into another run.
// Never infer provider consumption, acknowledgement or task success here.
export function deliveryObservation(projection,messageId,now){
  const message=projection.messages?.find(m=>m.id===messageId&&m.role==='user');
  const item=projection.turnItems?.find(i=>i.type==='user_message'&&i.messageId===messageId);
  if(!message&&!item)return null;
  if(message?.threadId&&message.threadId!==projection.thread.id||item?.threadId&&item.threadId!==projection.thread.id)
    throw Object.assign(Error('identity_mismatch'),{reason:'identity_mismatch'});
  if(message?.runId&&item?.runId&&message.runId!==item.runId)
    throw Object.assign(Error('identity_mismatch'),{reason:'identity_mismatch'});
  const runId=message?.runId??item?.runId??null;
  const run=projection.runs?.find(r=>r.id===runId);
  return {message_id:messageId,run_id:runId,run_status:run?.status??null,
    input_intent:['turn_start','queued_turn','steer','promoted_queued_to_steer'].includes(item?.inputIntent)?item.inputIntent:null,
    observed_at:new Date(now).toISOString()};
}
