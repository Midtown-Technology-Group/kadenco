// SPDX-License-Identifier: AGPL-3.0-or-later
const el = (id) => document.getElementById(id) as HTMLInputElement;
const status = (text, error = false) => {
  el("status").textContent = text;
  el("status").classList.toggle("error", error);
  for (const name of ["share", "join", "request"]) {
    if (dialog(name).open && (error || text.startsWith("Guest link"))) {
      el(name + "-status").textContent = text;
      el(name + "-status").classList.toggle("error", error);
    }
  }
};
const dialog = (name) => document.getElementById(name + "-dialog") as HTMLDialogElement;
function closeDialogs() {
  for (const name of ["share", "join", "request"]) dialog(name).close();
}
for (const name of ["share", "join", "request"]) {
  el("close-" + name).onclick = () => dialog(name).close();
  dialog(name).addEventListener("cancel", (event) => {
    if (locked || el("join-thread").disabled) event.preventDefault();
  });
}
el("cancel-join").onclick = () => dialog("join").close();
el("decline-join").onclick = () => {
  location.hash = "";
};
el("review-join").onclick = () => {
  el("join-status").textContent = "";
  dialog("join").showModal();
};
let inviteStep = "recipient";
function setInviteStep(review) {
  inviteStep = review ? "access" : "recipient";
  el("invite-recipient").hidden = review;
  el("invite-review").hidden = !review;
  el("invite-back").hidden = !review;
  el("invite-next").hidden = review;
  el("create-invite").hidden = !review;
  el("recipient-step").removeAttribute("aria-current");
  el("access-step").removeAttribute("aria-current");
  el(review ? "access-step" : "recipient-step").setAttribute("aria-current", "step");
}
el("invite-next").onclick = () => {
  if (!el("invite-email").reportValidity()) return;
  el("review-email").textContent = el("invite-email").value.trim().toLowerCase();
  el("review-target").textContent = `${target.host} / ${target.thread_id}`;
  setInviteStep(true);
  el("create-invite").focus();
};
el("invite-back").onclick = () => {
  setInviteStep(false);
  el("invite-email").focus();
};
let me,
  target,
  current,
  stream,
  adminData,
  locked = false,
  navigation = 0;
const query = (scope, extra = {}) => new URLSearchParams({ ...scope, ...extra }).toString();
const active = (scope, generation) => {
  const hash = new URLSearchParams(location.hash.slice(1));
  return (
    generation === navigation &&
    target?.host === scope.host &&
    target?.thread_id === scope.thread_id &&
    hash.get("host") === scope.host &&
    hash.get("thread_id") === scope.thread_id
  );
};
async function api(path: string, body?: unknown) {
  const response = await fetch("/collaborate/api/" + path, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json", "x-t3-collaboration": "1" } : {},
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const result = await response.json();
  if (!response.ok) throw Error(result.reason ?? "Request unavailable");
  return result;
}
function node(tag, text, parent) {
  const n = document.createElement(tag);
  n.textContent = text;
  if (parent) parent.append(n);
  return n;
}
function selectTarget(scope) {
  location.hash = query(scope);
}
const pendingKey = (scope) =>
  "t3-collaboration:" + me.identity_scope + ":" + me.subject + ":" + query(scope);
async function work(scope, generation, fn) {
  if (locked || !current || !active(scope, generation)) return;
  locked = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    await fn();
  } catch (e) {
    if (active(scope, generation)) status(e.message + " · No automatic resend.", true);
  } finally {
    locked = false;
    document.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}
async function loadMessages(scope, generation) {
  const { messages } = await api("messages?" + query(scope));
  if (active(scope, generation)) renderMessages(messages, scope, generation);
}
function renderMessages(messages, scope, generation) {
  if (!active(scope, generation)) return;
  el("requests").replaceChildren();
  el("requests-title").hidden = !messages.length;
  for (const r of messages) {
    const a = node("article", "", el("requests"));
    a.classList.add("guest-proposal");
    node("small", `${r.sender_email ?? r.sender} · ${r.state}`, a);
    node("pre", r.text, a);
    if (["reserved", "uncertain"].includes(r.state))
      node("p", "Unresolved delivery. Keep the same request; never resend under a new ID.", a);
    if (r.receipt) {
      const receipt = r.receipt;
      node(
        "p",
        receipt.completed
          ? "Execution: completed"
          : receipt.terminal
            ? `Execution: ${receipt.run_status}`
            : `Delivery: ${receipt.submission ?? "unconfirmed"}; execution: ${receipt.run_status ?? "not yet observed"}`,
        a,
      );
      if (receipt.result) node("pre", receipt.result, a);
      const details = node("details", "", a);
      node("summary", "Delivery details", details);
      node("p", "Run: " + (receipt.run_id ?? "not yet bound"), details);
      node(
        "p",
        "Agent acknowledgement: " + (receipt.agent_acknowledged ? "recorded" : "not recorded"),
        details,
      );
      node(
        "p",
        receipt.result_fresh
          ? "Result verified by current native readback."
          : "Result freshness not established by this receipt.",
        details,
      );
    }
    if (r.state === "pending" && current.permissions.capabilities.includes("review"))
      for (const action of ["send", "dismiss"]) {
        if (
          action === "send" &&
          r.sender === me.subject &&
          !current.permissions.capabilities.includes("send")
        )
          continue;
        const b = node("button", action === "send" ? "Approve and send" : "Dismiss", a);
        b.onclick = () => {
          if (!active(scope, generation) || !current) return;
          const source = current.thread.source_run_id;
          void work(scope, generation, async () => {
            await api("decisions", {
              ...scope,
              message_id: r.message_id,
              action,
              ...(action === "send" ? { source_run_id: source } : {}),
            });
            await loadMessages(scope, generation);
          });
        };
      }
    if (["reserved", "accepted", "uncertain"].includes(r.state)) {
      const b = node("button", "Check exact delivery receipt", a);
      b.onclick = () =>
        work(scope, generation, async () => {
          const receipt = await api("receipt?" + query(scope, { message_id: r.message_id }));
          await loadMessages(scope, generation);
          if (active(scope, generation))
            status(
              receipt.receipt?.completed
                ? "Execution completed."
                : `Delivery: ${receipt.state}. Acceptance and completion are separate.`,
            );
        });
    }
  }
}
function snapshot(data, scope, generation) {
  if (!active(scope, generation)) return;
  if (data.thread.thread_id !== scope.thread_id) throw Error("Thread identity mismatch");
  current = data;
  el("title").textContent = data.thread.title;
  el("disclosure").textContent = data.history;
  if (data.messages) renderMessages(data.messages, scope, generation);
  if (me.owner && data.invitations) renderInvitations(data.invitations, scope, generation);
  el("timeline").replaceChildren();
  for (const item of data.items) {
    const a = node("article", "", el("timeline"));
    node("small", `${item.role} · ${item.status}${item.truncated ? " · truncated" : ""}`, a);
    node("pre", item.text, a);
  }
  const caps = data.permissions.capabilities,
    canSend = caps.includes("send");
  el("compose").hidden = !caps.includes("propose");
  el("submit").textContent = canSend ? "Send to T3" : "Propose message";
  el("send-mode").textContent = canSend
    ? "Your permission allows a new T3 turn without owner review. Existing T3 execution approvals still apply."
    : "Your message waits for an authorized reviewer. Proposing it starts no T3 run.";
  el("access").hidden = !me.owner;
  el("copy").hidden = false;
  el("share-guest").hidden = !me.owner;
  status(`${data.thread.status} · ${data.thread.model} · live`);
}
async function loadAdmin(scope, generation) {
  const data = await api("admin?" + query(scope));
  if (!active(scope, generation)) return;
  adminData = data;
  el("user").replaceChildren();
  for (const user of data.identities) {
    const option = node("option", user.email, el("user"));
    option.value = user.subject;
  }
  renderInvitations(data.invitations ?? [], scope, generation);
  showGrant();
}
function renderInvitations(invitations, scope, generation) {
  if (!active(scope, generation)) return;
  el("invitations").replaceChildren();
  for (const invitation of invitations) {
    const row = node("article", "", el("invitations"));
    node(
      "p",
      `${invitation.email} - ${invitation.state} - expires ${new Date(invitation.expires_at).toLocaleString()}`,
      row,
    );
    if (invitation.state !== "revoked") {
      const revoke = node("button", "Stop sharing with " + invitation.email, row);
      revoke.onclick = () =>
        work(scope, generation, async () => {
          await api("invitations/revoke", { ...scope, invitation_id: invitation.id });
          await loadAdmin(scope, generation);
          if (active(scope, generation))
            status("Invitation revoked. Previously accepted T3 work is not cancelled.");
        });
    }
  }
}
function showGrant() {
  if (!adminData) return;
  const g = adminData.grants.find((g) => g.subject === el("user").value);
  for (const cap of ["view", "propose", "send", "review"])
    el(cap).checked = (g?.capabilities ?? ["view"]).includes(cap);
  const expiry = new Date(g?.expires_at ?? Date.now() + 86400000);
  el("expiry").value = new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
}
el("user").onchange = showGrant;
el("send").onchange = () => {
  if (el("send").checked) {
    el("view").checked = true;
    el("propose").checked = true;
  }
};
el("propose").onchange = () => {
  if (el("propose").checked) el("view").checked = true;
  else el("send").checked = false;
};
el("review").onchange = () => {
  if (el("review").checked) el("view").checked = true;
};
el("view").onchange = () => {
  if (!el("view").checked) for (const cap of ["propose", "send", "review"]) el(cap).checked = false;
};
function unavailable() {
  closeDialogs();
  current = null;
  el("title").textContent = "Shared thread unavailable";
  el("disclosure").textContent = "";
  el("compose").hidden = true;
  el("access").hidden = true;
  el("copy").hidden = true;
  el("share-guest").hidden = true;
  el("guest-share-panel").hidden = true;
  el("join-invitation").hidden = true;
  el("requests-title").hidden = true;
  el("timeline").replaceChildren();
  el("requests").replaceChildren();
  el("guest-access").hidden = false;
  el("guest-identity").textContent =
    `Ask the owner to select ${me.email} (account ${me.subject}). No access request has been sent.`;
}
el("retry-access").onclick = () => void open();
async function open() {
  closeDialogs();
  el("sharing-request-card").hidden = true;
  const generation = ++navigation;
  stream?.close();
  current = null;
  adminData = null;
  el("invite-email").value = "";
  el("invite-link").value = "";
  el("invite-link-label").hidden = true;
  el("copy-invite").hidden = true;
  el("invitations").replaceChildren();
  el("message").value = "";
  el("compose").hidden = true;
  el("access").hidden = true;
  el("copy").hidden = true;
  el("share-guest").hidden = true;
  el("guest-share-panel").hidden = true;
  el("join-invitation").hidden = true;
  el("requests").replaceChildren();
  el("timeline").replaceChildren();
  el("guest-access").hidden = true;
  el("title").textContent = "Choose a shared thread";
  el("disclosure").textContent = "";
  el("requests-title").hidden = true;
  const hash = new URLSearchParams(location.hash.slice(1));
  if (!hash.get("host") || !hash.get("thread_id")) {
    target = null;
    return;
  }
  const scope = Object.freeze({ host: hash.get("host"), thread_id: hash.get("thread_id") });
  target = scope;
  if (hash.get("sharing_request_id")) {
    const requestId = hash.get("sharing_request_id");
    try {
      const r = await api("sharing-request?" + query({ request_id: requestId }));
      if (!active(scope, generation)) return;
      if (r.host !== scope.host || r.thread_id !== scope.thread_id)
        throw Error("identity_mismatch");
      el("sharing-request-card").hidden = false;
      el("request-reason").textContent = r.reason;
      el("request-source").textContent = `${r.host} / ${r.thread_id} - ${r.state}`;
      el("request-email").textContent = r.email;
      el("request-target").textContent = `${r.host} / ${r.thread_id}`;
      el("request-run").textContent = r.run_id;
      el("request-status").textContent = `Request: ${r.state}. No access granted by this request.`;
      el("request-link-label").hidden = true;
      el("request-actions").hidden = !["pending", "approving"].includes(r.state);
      const showResult = (result) => {
        el("request-status").textContent = `Request: ${result.state}. No T3 work started.`;
        el("request-actions").hidden = true;
        if (result.invitation_id) {
          const url = new URL("/collaborate/", location.origin);
          url.hash = query({ ...scope, invitation_id: result.invitation_id });
          el("request-link").value = url.href;
          el("request-link-label").hidden = false;
        }
      };
      if (r.state === "approved") showResult(r);
      el("review-sharing-request").onclick = () => dialog("request").showModal();
      let deciding = false;
      const decide = async (decision) => {
        if (deciding || !active(scope, generation)) return;
        deciding = true;
        el("approve-sharing-request").disabled = el("decline-sharing-request").disabled = true;
        try {
          const result = await api("sharing-decisions", { request_id: requestId, decision });
          if (active(scope, generation)) showResult(result);
        } catch (e) {
          if (active(scope, generation))
            el("request-status").textContent =
              `${e.message}. Review the same request to reconcile; no automatic retry.`;
        } finally {
          deciding = false;
          el("approve-sharing-request").disabled = el("decline-sharing-request").disabled = false;
        }
      };
      el("approve-sharing-request").onclick = () => void decide("approve");
      el("decline-sharing-request").onclick = () => void decide("decline");
      status("Sharing request awaits your review. Agent text is evidence, not authority.");
    } catch (e) {
      if (active(scope, generation)) status(e.message, true);
    }
    return;
  }
  if (hash.get("invitation_id")) {
    el("join-invitation").hidden = false;
    el("join-identity").textContent =
      `Signed in as ${me.email}. Only the invited account can join.`;
    el("join-account").textContent = me.email;
    el("join-target").textContent = `${scope.host} / ${scope.thread_id}`;
    const invitationId = hash.get("invitation_id");
    el("join-thread").onclick = async () => {
      if (!active(scope, generation)) return;
      el("join-thread").disabled = true;
      try {
        await api("invitations/claim", { ...scope, invitation_id: invitationId });
        if (active(scope, generation)) selectTarget(scope);
      } catch (e) {
        if (active(scope, generation)) status(e.message + ". No T3 work started.", true);
      } finally {
        el("join-thread").disabled = false;
      }
    };
    status("Invitation ready. Join with the account named by the owner.");
    return;
  }
  status("Loading shared thread…");
  try {
    const data = await api("view?" + query(scope));
    if (!active(scope, generation)) return;
    snapshot(data, scope, generation);
    await loadMessages(scope, generation);
    if (!active(scope, generation)) return;
    if (me.owner) await loadAdmin(scope, generation);
    if (!active(scope, generation)) return;
    const pending = localStorage.getItem(pendingKey(scope));
    if (pending) {
      el("message").value = JSON.parse(pending).text;
      status(
        "A prior send may have been stored. Submit unchanged to reconcile the same request; no automatic resend.",
        true,
      );
    }
    const connection = new EventSource("/collaborate/api/stream?" + query(scope));
    stream = connection;
    connection.addEventListener("snapshot", (event) => {
      if (!active(scope, generation)) {
        connection.close();
        return;
      }
      try {
        snapshot(JSON.parse(event.data), scope, generation);
      } catch {
        connection.close();
        status("Live response unavailable.", true);
      }
    });
    connection.addEventListener("unavailable", (event) => {
      connection.close();
      if (!active(scope, generation)) return;
      unavailable();
      status(JSON.parse(event.data).reason, true);
    });
    connection.onerror = () => {
      if (active(scope, generation))
        status(
          "Live connection interrupted; reconnecting read-only. Messages are never resent automatically.",
          true,
        );
    };
  } catch (e) {
    if (active(scope, generation)) {
      unavailable();
      status(e.message, true);
    }
  }
}
el("share-guest").onclick = () => {
  if (me?.owner && current) {
    setInviteStep(false);
    el("invite-form").hidden = false;
    el("share-status").textContent = "";
    el("guest-share-panel").hidden = false;
    dialog("share").showModal();
  }
};
el("invite-form").onsubmit = (event) => {
  event.preventDefault();
  if (inviteStep !== "access") {
    el("invite-next").click();
    return;
  }
  const scope = target,
    generation = navigation;
  if (!me?.owner || !current) return;
  void work(scope, generation, async () => {
    const key = pendingKey(scope) + ":invitation",
      email = el("invite-email").value.trim().toLowerCase();
    let request = JSON.parse(localStorage.getItem(key) ?? "null");
    if (request && request.expires_at <= Date.now()) {
      localStorage.removeItem(key);
      request = null;
    }
    if (request && request.email !== email)
      throw Error("Reconcile the previous invitation before inviting a different account");
    if (!request) {
      request = {
        ...scope,
        email,
        request_id: crypto.randomUUID(),
        expires_at: Date.now() + 82800000,
      };
      localStorage.setItem(key, JSON.stringify(request));
    }
    const invitation = await api("invitations", request);
    if (!active(scope, generation)) return;
    localStorage.removeItem(key);
    const link = new URL("/collaborate/", location.origin);
    link.hash = query({ ...scope, invitation_id: invitation.id });
    el("invite-link").value = link.href;
    el("invite-link-label").hidden = false;
    el("copy-invite").hidden = false;
    el("invite-form").hidden = true;
    await loadAdmin(scope, generation);
    if (active(scope, generation))
      status(
        "Guest link ready. Only the named signed-in account can claim it; every proposal waits for review.",
      );
  });
};
el("copy-invite").onclick = async () => {
  if (!me?.owner || !current) return;
  try {
    await navigator.clipboard.writeText(el("invite-link").value);
    status("Guest link copied.");
  } catch {
    el("invite-link").focus();
    el("invite-link").select();
    status("Copy the selected guest link.");
  }
};
el("copy-sign-in").onclick = async () => {
  if (!me?.owner) return;
  try {
    await navigator.clipboard.writeText(el("sign-in-link").value);
    status("Sign-in link copied. Grant the signed-in account access to each thread separately.");
  } catch {
    el("sign-in-link").focus();
    el("sign-in-link").select();
    status("Copy the selected sign-in link. No thread access has been granted.");
  }
};
el("open").onsubmit = (event) => {
  event.preventDefault();
  selectTarget({ host: el("host").value.trim(), thread_id: el("thread").value.trim() });
};
el("copy").onclick = () => {
  const scope = target,
    generation = navigation,
    url = location.href;
  void work(scope, generation, async () => {
    await navigator.clipboard.writeText(url);
    if (active(scope, generation))
      status("Link copied. Only explicitly permitted MTG users can open it.");
  });
};
el("compose").onsubmit = (event) => {
  event.preventDefault();
  if (!current || !target) return;
  const scope = target,
    generation = navigation,
    source = current.thread.source_run_id,
    canSend = current.permissions.capabilities.includes("send"),
    key = pendingKey(scope),
    text = el("message").value.trim();
  void work(scope, generation, async () => {
    let p = JSON.parse(localStorage.getItem(key) ?? "null");
    if (p && (p.text !== text || p.host !== scope.host || p.thread_id !== scope.thread_id))
      throw Error("Reconcile the unchanged prior message before creating another request");
    if (!p) {
      p = {
        ...scope,
        request_id: crypto.randomUUID(),
        text,
        intent: canSend ? "send" : "propose",
        ...(canSend ? { source_run_id: source } : {}),
      };
      localStorage.setItem(key, JSON.stringify(p));
    }
    const r = await api("messages", p);
    await loadMessages(scope, generation);
    if (["reserved", "uncertain"].includes(r.state)) {
      if (active(scope, generation))
        status(
          "Delivery is unresolved. Keep this exact request; submit unchanged only to reconcile. No automatic resend.",
          true,
        );
      return;
    }
    localStorage.removeItem(key);
    if (active(scope, generation)) {
      el("message").value = "";
      status(`Message ${r.state}. No additional send was made.`);
    }
  });
};
async function saveGrant(revoke = false) {
  if (!target || !current || !adminData) return;
  const scope = target,
    generation = navigation,
    subject = el("user").value,
    g = adminData.grants.find((g) => g.subject === subject),
    body = {
      ...scope,
      subject,
      expected_revision: g?.revision ?? 0,
      capabilities: revoke
        ? []
        : ["view", "propose", "send", "review"].filter((cap) => el(cap).checked),
      expires_at: revoke ? Date.now() + 60000 : new Date(el("expiry").value).getTime(),
    };
  await work(scope, generation, async () => {
    await api("grants", body);
    await loadAdmin(scope, generation);
    if (active(scope, generation))
      status(revoke ? "Access revoked. Accepted T3 work is not cancelled." : "Permissions saved.");
  });
}
el("grant").onsubmit = (event) => {
  event.preventDefault();
  void saveGrant();
};
el("revoke").onclick = () => void saveGrant(true);
try {
  me = await api("me");
  el("identity").textContent = `Signed in as ${me.email}`;
  el("open").hidden = !me.owner;
  el("sharing-help").hidden = !me.owner;
  el("sign-in-link").value = new URL("/collaborate/", location.origin).href;
  const { threads } = await api("threads");
  for (const t of threads) {
    const a = node("a", `${t.host} / ${t.thread_id}`, el("threads"));
    a.href = "#" + query({ host: t.host, thread_id: t.thread_id });
  }
  addEventListener("hashchange", () => void open());
  await open();
} catch (e) {
  status(e.message, true);
}
