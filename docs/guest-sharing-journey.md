# Guest sharing journey

Reference: the owner's supplied 18.6-second upstream demo, also announced in
[Theo's Share with guest post](https://x.com/theo/status/2114238361967988747).
This is an independent implementation in Kadenco; no T3 application source is
modified or copied. It joins the alpha.3 candidate.

From an opened thread, the owner chooses **Share with guest**, enters the
colleague's work email and chooses **Create link**. The owner copies that
thread's invitation and sends it using their normal communication channel.
No email is sent by Kadenco. The invitation expires within24 hours.

The colleague signs in through the existing MTG identity boundary and selects
**Join thread**. The verified account email must match the invitation. The
first claim binds it to that account subject and grants View + Propose for the
exact host, thread and native project until the invitation's original expiry.
The colleague can follow the conversation and submit a proposed message. The
owner sees it arrive with its author's email and chooses **Approve and send**
or **Dismiss**. Only approval invokes the existing bounded native send path.
Both views retain the distinction between submission, acknowledgement and
completion, and can reconcile the exact delivery receipt. A reload does not
resend an accepted proposal.

**Stop sharing** revokes an unclaimed invitation, or its original claimed grant.
It preserves any later grant explicitly managed by the owner; use the existing
access panel to revoke that grant. It cannot cancel previously accepted native
work. Expired/revoked invitations never revive access, and an invitation never
overwrites any existing grant. If the colleague already has a grant, manage it
through the existing access panel rather than issuing a replacement invitation.

The link is a navigation reference, not a bearer credential. It cannot enroll
an unadmitted identity provider, grant Send/Review, or broaden broker read scope.
Guest history remains the existing filtered recent user/assistant conversation:
no additional tool logs, reasoning, attachments or inherited histories are exposed.
Changing that projection is outside this slice. Existing standing subscriptions,
credentials, signing, models, native runtime settings and approvals are unchanged.

Acceptance uses synthetic accounts with a recording native boundary: owner
creates a link before first guest sign-in; guest joins and proposes; owner sees
it live, approves, and both reconcile completion; reload makes no extra send;
revocation clears the guest view. Regression tests cover wrong/foreign identity,
expiry, duplicate claim, request conflict, existing grant and a revocation race.
Live acceptance still requires a real colleague's own sign-in and an explicit
owner invitation; synthetic evidence is not a live-user or native-execution claim.
