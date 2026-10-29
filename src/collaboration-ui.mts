// SPDX-License-Identifier: AGPL-3.0-or-later
const el = (id) => document.getElementById(id) as HTMLInputElement;
const status = (text, error = false) => {
  el("status").textContent = text;
  el("status").classList.toggle("error", error);
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
    node("small", `${r.sender} · ${r.state}`, a);
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
  showGrant();
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
  current = null;
  el("title").textContent = "Shared thread unavailable";
  el("disclosure").textContent = "";
  el("compose").hidden = true;
  el("access").hidden = true;
  el("copy").hidden = true;
  el("requests-title").hidden = true;
  el("timeline").replaceChildren();
  el("requests").replaceChildren();
  el("guest-access").hidden = false;
  el("guest-identity").textContent =
    `Ask the owner to select ${me.email} (account ${me.subject}). No access request has been sent.`;
}
el("retry-access").onclick = () => void open();
async function open() {
  const generation = ++navigation;
  stream?.close();
  current = null;
  adminData = null;
  el("message").value = "";
  el("compose").hidden = true;
  el("access").hidden = true;
  el("copy").hidden = true;
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
el("cadence-refresh").onclick = async () => {
  const container = el("cadence-goals");
  container.replaceChildren();
  try {
    let cursor;
    do {
      const page = await api("cadence" + (cursor ? "?" + query({ cursor }) : ""));
      for (const goal of page.goals) {
        const article = node("article", "", container);
        node("h3", `${goal.title} · ${goal.bucket}`, article);
        node(
          "p",
          `Phase: ${goal.phase}. Next: ${goal.next_action.owner ?? "unowned"} · ${goal.next_action.description}`,
          article,
        );
        node(
          "p",
          `Last progress: ${goal.last_meaningful_progress ?? "not observed"}. Activity: ${goal.last_activity ?? "not observed"}.`,
          article,
        );
        const button = node("button", "Read exact goal evidence", article);
        button.onclick = async () => {
          try {
            const detail = await api("cadence-goal?" + query({ goal_id: goal.goal_id }));
            let evidence = article.querySelector("pre");
            if (!evidence) evidence = node("pre", "", article);
            evidence.textContent = JSON.stringify(detail, null, 2);
          } catch {
            status("Goal evidence unavailable. No action was sent.", true);
          }
        };
      }
      cursor = page.next_cursor;
    } while (cursor);
  } catch {
    status("Cadence overview unavailable. No action was sent.", true);
  }
};
try {
  me = await api("me");
  el("cadence").hidden = !me.cadence_available;
  el("identity").textContent = `Signed in as ${me.email}`;
  el("open").hidden = !me.owner;
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
