# Guest sharing journey

Reference: the owner's supplied 18.6-second upstream demo, also announced in
[Theo's Share with guest post](https://x.com/theo/status/2114238361967988747).
This is an independent implementation in Kadenco; no T3 application source is
modified or copied. It joins the alpha.3 candidate.

From an opened thread, the owner chooses **Share with guest**, enters the
colleague's work email and chooses **Create link**. The owner copies that
thread's invitation and sends it using their normal communication channel.
No email is sent by Kadenco. The invitation expires within 24 hours.

The colleague signs in through the existing MTG identity boundary and selects
**Join** after entering a display name. The verified account email must match the invitation. The
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

Identity provenance: Kadenco validates the signed Access application JWT and
independently resolves its identity with Access. Subject and email must match
that response, and the identity must come from the configured exact Entra IdP.
Cloudflare documents the application-token email as verified by the IdP:
[application token claims](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/).
There is no assumed `verified_primary_email` claim. This trusts the configured
Entra identity boundary; it does not provide independent mailbox verification.

The browser requests a 23-hour invitation to leave clock-skew margin below the
24-hour server maximum. It retains uncertain request IDs until their expiry;
only expired requests are discarded, so near-expiry live invitations cannot
be duplicated by a fresh request.

## Access review UI

The alpha.4 candidate follows T3's inline request, review dialog and explicit
confirmation pattern. Reference: upstream `LinkRequestCard.tsx` and its
`WizardHeader`/`WizardPanel`/`WizardFooter` at source
`6fc9144a60c4a5f45089316ddd5f7371bafd3bf2`. This is an independent HTML/CSS
implementation; no native T3 source is modified or copied.

Owners choose the colleague, continue to review the exact account/thread,
View + Propose scope and 23-hour lifetime, then create the invitation.
In alpha.6, guests enter their display name on the standalone join page and
select **Join**, alongside the explanation that the owner approves each message.
The earlier alpha.4 guest Decline/Review access dialog is historical and removed.
Owner request-review dialogs still trap focus and restore it to the trigger;
navigating or losing access closes stale dialogs. In-flight submission uses
the existing synchronous duplicate guard and durable request UUID.

The follow-on thread request interface uses the same invitation authorization.
`request_thread_sharing` accepts only the bound caller's exact thread, observed
active run, stable UUID, recipient email and reason. `get_thread_sharing_request`
reconciles that exact receipt. New tools require the
`x-kadenco-sharing-requests: 1` discovery capability; existing callers retain
their prior surface. Updated public terminal adapters support `request_sharing`
and `get_sharing` using the same connection file and credential.

The receipt returns an owner review URL. The owner sees the reason as untrusted
agent text, exact host/thread/run, recipient, View + Propose scope and bounded
lifetime, then explicitly authorizes or declines. Approval reserves an auditable
state before native reads and creates one invitation under the same UUID;
uncertain outcomes remain approving until the owner reconciles that request.
Caller revocation/rebinding, IdP scope changes and project drift fail closed,
including the final invitation transaction. Decline never creates a grant.
Requests expire after 24 hours; approval creates an invitation for at most
23 hours and never extends the request's original expiry. A source read proves
the observed native run, not an atomic provider guarantee that it remains active
at storage time. The inert request cannot grant access or start execution.

This does not inject a custom card into T3's native timeline: no supported
extension surface for that was found. The requesting thread presents the
returned review link; the portal owns the matching review modal. No native T3
source, pairing codes, machine-link grants or credentials are changed.

## Native guest screenshots

Alpha.6 replaces the guest review dialog with the supplied native standalone
join form: Your name, Join, and the owner-approval explanation. A display name
is stored on the original exact grant and copied into proposal receipts; it
never replaces the signed-in subject/email or changes capabilities. Duplicate
claim preserves the original label. Existing Access sign-in remains required
before the page is served, so this is not anonymous bearer-link admission.

The joined guest view hides owner/navigation chrome, displays the actual thread
title and remaining grant lifetime, formats safe conversation text with user
bubbles, and pins the model/approval composer to the bottom. The model is read
from native metadata; no provider logo, attachment access or reasoning/tool
history is invented. Expiry/revocation clears the conversation and header.
Source identity, exact scope, proposal approval and native execution controls
remain unchanged. Owner administration remains a separate existing view.
