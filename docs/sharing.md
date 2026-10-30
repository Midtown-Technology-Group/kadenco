# Share a thread with an MTG colleague

The owner and colleague use their own existing MTG sign-ins. A link identifies a
thread; it does not carry permission or an owner credential.

1. Open the configured collaboration portal at `/collaborate/`. As owner, copy
   the **Colleague sign-in link** and send it to your colleague. This link has
   no thread target, token or credential. They sign in once so their verified
   account becomes selectable; no thread access is created by signing in.
2. Open the exact host/thread using the owner form or an existing sharing link.
   In **Manage access to this thread**, select that colleague's verified
   account. Start with **View** for following progress, choose the intended
   expiry and save. Check the saved permission before sharing the thread URL.
3. Click **Copy link** on the thread. The colleague opens it, signs in, and
   uses **Check access again** if they opened it before you granted access.
4. Revoke access in the same panel when appropriate. Revocation clears the
   thread view; it does not cancel previously accepted T3 work.

View does not permit sending messages. Propose stores a message for an
authorized reviewer; Send permits a new turn subject to existing native checks.
Grant those capabilities only when intended. Sharing a native `t3-thread://`
link is useful for T3 navigation, but does not create a browser invitation or
permission in this portal.

The portal must already be configured behind its supported Entra/Access
identity boundary. This guide does not admit arbitrary external accounts,
change identity policy, auto-enroll colleagues, or extend grant expiry. A live
colleague acceptance needs that colleague's own login and an owner-selected
exact-thread grant. Synthetic browser tests prove the UI flow and revocation,
not a real colleague's login or access.
