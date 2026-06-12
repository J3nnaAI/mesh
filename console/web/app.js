/* ============================================================================
   Mesh Console — control-plane UI logic.
   Pure vanilla JS, no deps, same-origin relative fetches only.

   Security posture:
   - Every server-supplied value is rendered with textContent / DOM nodes,
     NEVER innerHTML — these are keys, tokens, grant ids, identities.
   - Loopback is trusted (no token needed). An optional bearer token (Settings,
     localStorage key "mesh.console.token") is sent on every request for remote
     use. can_manage from /whoami drives whether manage views render or show a
     calm "add a token" gate instead of firing requests that 401.
   - Polling pauses when the tab is hidden and resumes on return.
   ========================================================================== */
(() => {
  "use strict";

  const TOKEN_KEY = "mesh.console.token";
  const POLL_MS = 3000;

  /* ---- tiny DOM helpers ---- */
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text; // safe by construction
    return n;
  };
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };

  /* ---- state ---- */
  let token = "";
  try { token = localStorage.getItem(TOKEN_KEY) || ""; } catch { token = ""; }
  let canManage = false;
  let enrollTimer = null;
  let visible = !document.hidden;

  /* ---- fetch wrapper: relative URL, optional bearer, JSON or status ---- */
  async function api(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    if (token) headers["Authorization"] = "Bearer " + token;
    if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
    const res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
    if (res.status === 204) return { ok: true, status: 204, data: null };
    let data = null;
    const ct = res.headers.get("content-type") || "";
    try { data = ct.includes("application/json") ? await res.json() : await res.text(); }
    catch { data = null; }
    return { ok: res.ok, status: res.status, data };
  }

  function errText(r, fallback) {
    if (r && typeof r.data === "string" && r.data.trim()) return r.data.trim();
    if (r && r.data && r.data.error) return r.data.error;
    if (r && r.status) return fallback + " (" + r.status + ")";
    return fallback;
  }

  /* ---- formatting (server times are UNIX SECONDS) ---- */
  function relTime(unixSeconds) {
    if (!unixSeconds || typeof unixSeconds !== "number") return "—";
    const diff = Math.floor(Date.now() / 1000) - unixSeconds;
    if (diff < 0) return "just now";
    if (diff < 5) return "just now";
    if (diff < 60) return diff + "s ago";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
  }
  function truncMid(s, head = 10, tail = 8) {
    if (typeof s !== "string") return "—";
    if (s.length <= head + tail + 1) return s;
    return s.slice(0, head) + "…" + s.slice(-tail);
  }

  /* ---- toast ---- */
  let toastT = null;
  function toast(msg, kind) {
    const t = $("toast");
    t.textContent = msg;
    t.className = "toast show" + (kind === "err" ? " toast-err" : kind === "ok" ? " toast-ok" : "");
    t.hidden = false;
    clearTimeout(toastT);
    toastT = setTimeout(() => { t.className = "toast"; }, 2600);
  }

  /* ---- copy-to-clipboard (with fallback) ---- */
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch { /* fall through */ }
    try {
      const ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", "");
      ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch { return false; }
  }

  /* ========================================================================
     NAVIGATION
     ===================================================================== */
  const tabs = Array.from(document.querySelectorAll(".tab"));
  const views = {
    overview: $("view-overview"), enroll: $("view-enroll"),
    identities: $("view-identities"), revocation: $("view-revocation"), vault: $("view-vault"),
  };
  let current = "overview";

  function show(section) {
    if (!views[section]) section = "overview";
    current = section;
    for (const t of tabs) t.setAttribute("aria-selected", String(t.dataset.section === section));
    for (const k in views) {
      const v = views[k];
      const on = k === section;
      v.hidden = !on;
      v.classList.toggle("is-active", on);
    }
    // section-entry loads
    if (section === "enroll") { startEnrollPoll(); }
    else { stopEnrollPoll(); }
    if (section === "identities") loadUsers();
    if (section === "revocation") loadCRL();
    if (section === "vault") loadVault();
  }
  tabs.forEach((t) => t.addEventListener("click", () => show(t.dataset.section)));
  document.querySelectorAll("[data-goto]").forEach((b) =>
    b.addEventListener("click", () => show(b.dataset.goto)));

  /* ========================================================================
     OVERVIEW + WHOAMI (drives the manage gates)
     ===================================================================== */
  async function loadIdentity() {
    const r = await api("/whoami");
    const dot = $("whoDot"), label = $("whoLabel");
    if (!r.ok) {
      canManage = false;
      dot.className = "who-dot";
      label.textContent = "console unreachable";
    } else {
      canManage = !!(r.data && r.data.can_manage);
      const ident = r.data && r.data.identity;
      if (canManage) {
        dot.className = "who-dot manage";
        label.textContent = ident ? ident : "operator · loopback";
      } else {
        dot.className = "who-dot view";
        label.textContent = "view-only · add token";
      }
    }
    applyGates();
  }

  async function loadAuthority() {
    const r = await api("/authority");
    const keyEl = $("rootKey");
    if (r.ok && r.data && r.data.root_public_key) {
      const full = String(r.data.root_public_key);
      keyEl.textContent = truncMid(full, 14, 12);
      keyEl.title = full;
      keyEl.dataset.full = full;
      $("protoMajor").textContent = r.data.protocol_major != null ? String(r.data.protocol_major) : "—";
    } else {
      keyEl.textContent = "unavailable";
      keyEl.dataset.full = "";
      $("protoMajor").textContent = "—";
    }
  }

  async function loadVersion() {
    const r = await api("/version");
    const v = r.ok && r.data && r.data.console ? String(r.data.console) : "—";
    $("consoleVer").textContent = v;
    $("footVer").textContent = "console " + v;
  }

  async function loadVaultState() {
    const stateEl = $("vaultState");
    clear(stateEl);
    if (!canManage) {
      stateEl.appendChild(el("span", "dot dot-mute"));
      stateEl.appendChild(document.createTextNode("—"));
      return;
    }
    const r = await api("/vault");
    if (!r.ok || !r.data) {
      stateEl.appendChild(el("span", "dot dot-mute"));
      stateEl.appendChild(document.createTextNode("—"));
      return;
    }
    const locked = !!r.data.locked;
    stateEl.appendChild(el("span", "dot " + (locked ? "dot-locked" : "dot-open")));
    stateEl.appendChild(document.createTextNode(locked ? "Locked" : "Unlocked"));
  }

  async function loadPendingCount() {
    const countEl = $("pendingCount");
    const pulse = $("pendingPulse");
    if (!canManage) {
      countEl.textContent = "—";
      pulse.classList.remove("on");
      setBadge(0);
      return;
    }
    const r = await api("/enroll/pending");
    if (!r.ok || !r.data || !Array.isArray(r.data.pending)) {
      countEl.textContent = "—";
      pulse.classList.remove("on");
      setBadge(0);
      return;
    }
    const n = r.data.pending.length;
    countEl.textContent = String(n);
    pulse.classList.toggle("on", n > 0);
    setBadge(n);
  }

  function setBadge(n) {
    const b = $("pendingBadge");
    if (n > 0) { b.textContent = String(n); b.hidden = false; }
    else { b.hidden = true; }
  }

  /* ---- manage gates: render a calm placeholder instead of firing 401s ---- */
  function gateNode(targetSection) {
    const g = document.createDocumentFragment();
    g.appendChild(document.createTextNode(
      "These controls need management access. Served from the console on localhost this is automatic; for remote access, add a bearer token."));
    const btn = el("button", null, "Open Settings");
    btn.type = "button";
    btn.addEventListener("click", openSettings);
    g.appendChild(btn);
    return g;
  }
  function applyGates() {
    const map = [
      ["manageGateEnroll", "enrollList"],
      ["manageGateIdent",  null],
      ["manageGateVault",  null],
    ];
    for (const [gateId] of map) {
      const gate = $(gateId);
      if (!gate) continue;
      gate.hidden = canManage;
      if (!canManage) { clear(gate); gate.appendChild(gateNode()); }
    }
    // hide manage-only subpanels when view-only
    const identForms = $("revokeTokenPanel");
    const mintBtn = $("mintBtn");
    if (identForms) identForms.style.display = canManage ? "" : "none";
    if (mintBtn) mintBtn.style.display = canManage ? "" : "none";
    $("usersTable").style.display = canManage ? "" : "none";
    const vf = $("vaultForm"); if (vf) vf.closest(".panel").style.display = canManage ? "" : "none";
    $("handlesList").closest(".panel").style.display = canManage ? "" : "none";
  }

  async function refreshOverview() {
    await loadIdentity();           // sets canManage + gates first
    await Promise.all([loadAuthority(), loadVersion(), loadVaultState(), loadPendingCount()]);
  }

  /* ========================================================================
     ENROLLMENTS — auto-refreshing queue
     ===================================================================== */
  function emptyState(strong, detail) {
    const box = el("div", "empty");
    box.appendChild(el("span", "empty-mark"));
    box.appendChild(el("strong", null, strong));
    box.appendChild(document.createTextNode(detail));
    return box;
  }

  async function loadEnroll() {
    if (!canManage) { clear($("enrollList")); setBadge(0); return; } // the gate explains access; no empty-state
    const r = await api("/enroll/pending");
    if (!r.ok) {
      const list = $("enrollList"); clear(list);
      list.appendChild(emptyState("Queue unavailable",
        "Could not reach the enrollment queue. It will retry automatically."));
      return;
    }
    const pend = (r.data && Array.isArray(r.data.pending)) ? r.data.pending : [];
    renderEnroll(pend);
    setBadge(pend.length);
  }

  function renderEnroll(pending) {
    const list = $("enrollList");
    clear(list);
    if (!pending.length) {
      list.appendChild(emptyState("No pending requests",
        "New devices and agents appear here when they ask to join."));
      return;
    }
    // newest first
    pending.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    for (const req of pending) list.appendChild(enrollCard(req));
  }

  function enrollCard(req) {
    const kind = (req.kind === "agent") ? "agent" : "user";
    const card = el("article", "enroll-card kind-" + kind);

    const body = el("div", "ec-body");
    const krow = el("div", "ec-kindrow");
    krow.appendChild(el("span", "kind-tag " + kind, kind === "agent" ? "Agent" : "User"));
    const name = el("span", "ec-name", req.client_name || "(unnamed)");
    krow.appendChild(name);
    body.appendChild(krow);

    const meta = el("div", "ec-meta");
    if (kind === "user" && req.email) meta.appendChild(metaRow("email", req.email));
    if (kind === "agent") {
      if (req.subject) meta.appendChild(metaRow("node id", req.subject));
      if (req.tier != null) meta.appendChild(metaRow("tier", String(req.tier)));
    }
    body.appendChild(meta);

    const time = el("div", "ec-time", "requested " + relTime(req.created_at));
    body.appendChild(time);

    const actions = el("div", "ec-actions");
    const approve = el("button", "approve", "Approve");
    approve.type = "button";
    approve.addEventListener("click", () => openApprove(req));
    const deny = el("button", "deny", "Deny");
    deny.type = "button";
    deny.addEventListener("click", () => denyRequest(req));
    actions.appendChild(approve); actions.appendChild(deny);
    body.appendChild(actions);

    // OOB centerpiece
    const oob = el("div", "ec-oob");
    oob.appendChild(el("span", "oob-label", "out-of-band code"));
    oob.appendChild(el("span", "oob-code", req.oob || "———"));
    oob.appendChild(el("span", "oob-hint", "Matches the code on the requester's screen."));

    card.appendChild(body);
    card.appendChild(oob);
    return card;
  }
  function metaRow(label, value) {
    const d = el("div");
    d.appendChild(el("span", "lbl", label));
    d.appendChild(document.createTextNode(value));
    return d;
  }

  async function denyRequest(req) {
    const r = await api("/enroll/" + encodeURIComponent(req.id) + "/deny", { method: "POST" });
    if (r.ok) { toast("Request denied", "ok"); loadEnroll(); loadPendingCount(); }
    else toast(errText(r, "Deny failed"), "err");
  }

  /* ---- the approve CEREMONY: OOB shown large, pre-filled, explicit confirm.
         Approve returns only {status:"approved"} — no token is surfaced here
         (the user receives their token via their own enroll poll). ---- */
  function openApprove(req) {
    const card = $("modalCard");
    clear(card);
    card.appendChild(el("h2", null, "Confirm enrollment"));
    const sub = el("p", "m-sub");
    sub.appendChild(document.createTextNode("Approving "));
    sub.appendChild(el("strong", null, req.client_name || "this request"));
    sub.appendChild(document.createTextNode(
      kindWord(req) + ". Verify the code below MATCHES the code shown on the requester's device before you confirm."));
    card.appendChild(sub);

    const conf = el("div", "oob-confirm");
    conf.appendChild(el("span", "cap", "out-of-band code"));
    conf.appendChild(el("div", "big", req.oob || "———"));
    card.appendChild(conf);

    const warn = el("div", "m-warn");
    warn.appendChild(el("b", null, "Match first."));
    warn.appendChild(document.createTextNode(
      " The code is the authentication — a typed email or name alone can never become access."));
    card.appendChild(warn);

    const actions = el("div", "modal-actions");
    const cancel = el("button", "ghost", "Cancel");
    cancel.type = "button";
    cancel.addEventListener("click", closeModal);
    const confirm = el("button", "approve", "Codes match — approve");
    confirm.type = "button";
    confirm.addEventListener("click", async () => {
      confirm.disabled = true; cancel.disabled = true;
      confirm.textContent = "Approving…";
      const r = await api("/enroll/" + encodeURIComponent(req.id) + "/approve", {
        method: "POST",
        body: JSON.stringify({ oob: req.oob }),
      });
      if (r.ok) {
        closeModal();
        toast("Approved — credential delivered to the requester", "ok");
        loadEnroll(); loadPendingCount();
      } else {
        confirm.disabled = false; cancel.disabled = false;
        confirm.textContent = "Codes match — approve";
        toast(errText(r, "Approval failed"), "err");
      }
    });
    actions.appendChild(cancel); actions.appendChild(confirm);
    card.appendChild(actions);
    openModal();
  }
  function kindWord(req) {
    return req.kind === "agent"
      ? " — an AGENT will receive an authority-signed grant"
      : " — a USER will receive a bearer token";
  }

  /* ---- enroll polling lifecycle ---- */
  function startEnrollPoll() {
    loadEnroll();
    stopEnrollPoll();
    setLive(true);
    if (visible) enrollTimer = setInterval(() => { if (visible) loadEnroll(); }, POLL_MS);
  }
  function stopEnrollPoll() {
    if (enrollTimer) { clearInterval(enrollTimer); enrollTimer = null; }
  }
  function setLive(on) {
    const tag = $("enrollLive");
    if (!tag) return;
    tag.classList.toggle("paused", !on);
    tag.lastChild.textContent = on ? " live" : " paused";
  }

  /* ========================================================================
     IDENTITIES
     ===================================================================== */
  async function loadUsers() {
    if (!canManage) return;
    const body = $("usersBody");
    const empty = $("usersEmpty");
    const r = await api("/users");
    clear(body);
    if (!r.ok) {
      empty.hidden = false; clear(empty);
      empty.appendChild(emptyState("Could not load identities", "The console did not respond. Try again shortly."));
      return;
    }
    const users = (r.data && Array.isArray(r.data.users)) ? r.data.users : [];
    if (!users.length) {
      empty.hidden = false; clear(empty);
      empty.appendChild(emptyState("No identities yet",
        "Mint a token to create the first identity, or approve an enrollment request."));
      return;
    }
    empty.hidden = true;
    users.sort((a, b) => String(a.identity).localeCompare(String(b.identity)));
    for (const u of users) {
      const tr = el("tr");
      tr.appendChild(td(u.identity || "—", "id-identity"));
      const fpTd = el("td");
      fpTd.appendChild(el("span", "fp", u.token || "—"));
      tr.appendChild(fpTd);
      body.appendChild(tr);
    }
  }
  function td(text, cls) { const c = el("td", cls); c.textContent = text; return c; }

  // Mint token → POST /users → FULL token returned ONCE → copy-once modal.
  function openMint() {
    const card = $("modalCard");
    clear(card);
    card.appendChild(el("h2", null, "Mint a token"));
    card.appendChild(el("p", "m-sub",
      "Create a bearer token for an identity. One identity can hold several tokens — one per device or delegate."));
    const form = el("form", "stack-form");
    const lab = el("label"); lab.textContent = "Identity";
    const input = el("input", "mono-input");
    input.type = "text"; input.placeholder = "user@example.com"; input.required = true;
    input.setAttribute("spellcheck", "false");
    lab.appendChild(input);
    form.appendChild(lab);
    const actions = el("div", "modal-actions");
    const cancel = el("button", "ghost", "Cancel"); cancel.type = "button";
    cancel.addEventListener("click", closeModal);
    const submit = el("button", "primary", "Mint token"); submit.type = "submit";
    actions.appendChild(cancel); actions.appendChild(submit);
    form.appendChild(actions);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const identity = input.value.trim();
      if (!identity) return;
      submit.disabled = true; submit.textContent = "Minting…";
      const r = await api("/users", { method: "POST", body: JSON.stringify({ identity }) });
      if (r.ok && r.data && r.data.token) showTokenOnce(r.data.identity || identity, r.data.token);
      else { submit.disabled = false; submit.textContent = "Mint token"; toast(errText(r, "Mint failed"), "err"); }
    });
    card.appendChild(form);
    openModal();
    setTimeout(() => input.focus(), 50);
  }

  function showTokenOnce(identity, fullToken) {
    const card = $("modalCard");
    clear(card);
    card.appendChild(el("h2", null, "Token minted"));
    const sub = el("p", "m-sub");
    sub.appendChild(document.createTextNode("Bearer token for "));
    sub.appendChild(el("strong", null, identity));
    sub.appendChild(document.createTextNode("."));
    card.appendChild(sub);

    const reveal = el("div", "token-reveal");
    const code = el("code"); code.textContent = fullToken; // textContent — never innerHTML
    reveal.appendChild(code);
    const copy = el("button", "copy", "Copy");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      const ok = await copyText(fullToken);
      copy.classList.toggle("copied", ok);
      copy.textContent = ok ? "Copied" : "Copy failed";
      setTimeout(() => { copy.classList.remove("copied"); copy.textContent = "Copy"; }, 1600);
    });
    reveal.appendChild(copy);
    card.appendChild(reveal);

    const warn = el("div", "m-warn");
    warn.appendChild(el("b", null, "Shown once."));
    warn.appendChild(document.createTextNode(
      " This token is not stored and will never be shown again. Copy it now and hand it to the device securely."));
    card.appendChild(warn);

    const actions = el("div", "modal-actions");
    const done = el("button", "primary", "I've saved it");
    done.type = "button";
    done.addEventListener("click", () => { closeModal(); loadUsers(); });
    actions.appendChild(done);
    card.appendChild(actions);
  }

  // Revoke a token: the list only has MASKED fingerprints, and DELETE /users/<token>
  // matches the EXACT full token — so this must be a paste-the-full-token form.
  function wireRevokeToken() {
    const form = $("revokeTokenForm");
    const input = $("revokeTokenInput");
    const msg = $("revokeTokenMsg");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const tok = input.value.trim();
      msg.textContent = ""; msg.className = "form-msg";
      if (!tok) return;
      if (!window.confirm("Revoke this token? The device using it loses access immediately.")) return;
      const r = await api("/users/" + encodeURIComponent(tok), { method: "DELETE" });
      if (r.status === 204) {
        msg.textContent = "Token revoked."; msg.className = "form-msg ok";
        input.value = ""; toast("Token revoked", "ok"); loadUsers();
      } else if (r.status === 404) {
        msg.textContent = "No such token. Paste the complete token value (not the masked fingerprint).";
        msg.className = "form-msg err";
      } else {
        msg.textContent = errText(r, "Revoke failed"); msg.className = "form-msg err";
      }
    });
  }

  /* ========================================================================
     REVOCATION (CRL + revoke-by-grant-id)
     ===================================================================== */
  async function loadCRL() {
    const r = await api("/crl");
    const body = $("crlBody");
    const empty = $("crlEmpty");
    const meta = $("crlMeta");
    clear(body);
    if (!r.ok || !r.data) {
      empty.hidden = false; clear(empty);
      empty.appendChild(emptyState("CRL unavailable", "Could not load the revocation list."));
      meta.textContent = "—";
      return;
    }
    const revoked = (r.data.revoked && typeof r.data.revoked === "object") ? r.data.revoked : {};
    const ids = Object.keys(revoked);
    meta.textContent = (r.data.issued_at ? "issued " + relTime(r.data.issued_at) + " · " : "") + ids.length + " revoked";
    if (!ids.length) {
      empty.hidden = false; clear(empty);
      empty.appendChild(emptyState("Nothing revoked",
        "Revoked grants appear here. Revocation propagates to peers within the CRL interval (~30s)."));
      return;
    }
    empty.hidden = true;
    ids.sort((a, b) => (revoked[b] || 0) - (revoked[a] || 0));
    for (const id of ids) {
      const tr = el("tr");
      const idTd = el("td");
      const code = el("span", "fp"); code.textContent = truncMid(id, 12, 10); code.title = id;
      idTd.appendChild(code);
      tr.appendChild(idTd);
      tr.appendChild(td(relTime(revoked[id]), "fp fp-mute"));
      body.appendChild(tr);
    }
  }

  function wireRevokeGrant() {
    const form = $("revokeGrantForm");
    const input = $("revokeGrantInput");
    const msg = $("revokeGrantMsg");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const id = input.value.trim();
      msg.textContent = ""; msg.className = "form-msg";
      if (!id) return;
      if (!window.confirm("Revoke grant " + truncMid(id, 8, 6) + "? It cannot be renewed afterward.")) return;
      const r = await api("/grants/" + encodeURIComponent(id), { method: "DELETE" });
      if (r.status === 204) {
        msg.textContent = "Grant revoked — propagating to peers."; msg.className = "form-msg ok";
        input.value = ""; toast("Grant revoked", "ok"); loadCRL();
      } else if (!canManage && (r.status === 401 || r.status === 403)) {
        msg.textContent = "Management access required — add a token in Settings."; msg.className = "form-msg err";
      } else {
        msg.textContent = errText(r, "Revoke failed"); msg.className = "form-msg err";
      }
    });
  }

  /* ========================================================================
     VAULT
     ===================================================================== */
  async function loadVault() {
    const tag = $("vaultLockTag");
    const list = $("handlesList");
    const empty = $("handlesEmpty");
    if (!canManage) { tag.textContent = "—"; tag.className = "vault-lock"; return; }
    const r = await api("/vault");
    clear(list);
    if (!r.ok || !r.data) {
      tag.textContent = "unavailable"; tag.className = "vault-lock";
      empty.hidden = false; clear(empty);
      empty.appendChild(emptyState("Vault unavailable", "Could not read vault metadata."));
      return;
    }
    const locked = !!r.data.locked;
    tag.textContent = locked ? "Locked" : "Unlocked";
    tag.className = "vault-lock " + (locked ? "locked" : "open");
    const handles = Array.isArray(r.data.handles) ? r.data.handles : [];
    if (!handles.length) {
      empty.hidden = false; clear(empty);
      empty.appendChild(emptyState("No secrets stored",
        locked ? "The vault is locked. Unlock it on the console host to store secrets."
               : "Add a secret below. Only its handle name is ever listed here — values stay sealed."));
      return;
    }
    empty.hidden = true;
    // Each handle is {handle, desc, created} (values are never returned). Render the name; show the
    // description as a secondary line when present. Tolerate a plain-string form defensively.
    const items = handles.map((h) => (typeof h === "string" ? { handle: h } : (h || {})));
    items.sort((a, b) => String(a.handle).localeCompare(String(b.handle)));
    items.forEach((h) => {
      const li = el("li");
      const name = el("span", "handle-name"); name.textContent = h.handle || "—";
      li.appendChild(name);
      if (h.desc) { const d = el("span", "handle-desc"); d.textContent = h.desc; li.appendChild(d); }
      list.appendChild(li);
    });
  }

  function wireVaultForm() {
    const form = $("vaultForm");
    const msg = $("vaultMsg");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const handle = $("vaultHandle").value.trim();
      const value = $("vaultValue").value;
      const desc = $("vaultDesc").value.trim();
      msg.textContent = ""; msg.className = "form-msg";
      if (!handle || !value) { msg.textContent = "Handle and value are required."; msg.className = "form-msg err"; return; }
      const r = await api("/vault", { method: "POST", body: JSON.stringify({ handle, value, desc }) });
      if (r.ok && r.data && r.data.stored) {
        msg.textContent = "Sealed “" + r.data.stored + "”. Its value is now unreadable from here.";
        msg.className = "form-msg ok";
        $("vaultHandle").value = ""; $("vaultValue").value = ""; $("vaultDesc").value = "";
        toast("Secret sealed", "ok"); loadVault();
      } else {
        msg.textContent = errText(r, "Could not store secret"); msg.className = "form-msg err";
      }
    });
  }

  /* ========================================================================
     COPY (root key) + modal/settings plumbing
     ===================================================================== */
  document.querySelectorAll("[data-copy-target]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = $(btn.dataset.copyTarget);
      const full = (target && target.dataset.full) || (target && target.textContent) || "";
      if (!full || full === "—" || full === "unavailable") { toast("Nothing to copy", "err"); return; }
      const ok = await copyText(full);
      btn.classList.toggle("copied", ok);
      btn.textContent = ok ? "Copied" : "Copy failed";
      setTimeout(() => { btn.classList.remove("copied"); btn.textContent = "Copy"; }, 1600);
    });
  });

  function openModal() { const o = $("modal"); o.hidden = false; }
  function closeModal() { const o = $("modal"); o.hidden = true; clear($("modalCard")); }
  $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) closeModal(); });

  function openSettings() {
    $("tokenInput").value = token;
    $("tokenMsg").textContent = "";
    $("settingsPanel").hidden = false;
    setTimeout(() => $("tokenInput").focus(), 50);
  }
  function closeSettings() { $("settingsPanel").hidden = true; }
  $("settingsBtn").addEventListener("click", openSettings);
  $("settingsClose").addEventListener("click", closeSettings);
  $("settingsPanel").addEventListener("click", (e) => { if (e.target === $("settingsPanel")) closeSettings(); });

  $("tokenSave").addEventListener("click", async () => {
    token = $("tokenInput").value.trim();
    try { token ? localStorage.setItem(TOKEN_KEY, token) : localStorage.removeItem(TOKEN_KEY); } catch {}
    $("tokenMsg").textContent = "Saved. Re-checking access…"; $("tokenMsg").className = "form-msg ok";
    await refreshOverview();
    refreshCurrentView();
    $("tokenMsg").textContent = canManage ? "Management access confirmed." : "Token did not grant management access.";
    $("tokenMsg").className = "form-msg " + (canManage ? "ok" : "err");
  });
  $("tokenClear").addEventListener("click", async () => {
    token = ""; $("tokenInput").value = "";
    try { localStorage.removeItem(TOKEN_KEY); } catch {}
    $("tokenMsg").textContent = "Token cleared."; $("tokenMsg").className = "form-msg";
    await refreshOverview();
    refreshCurrentView();
  });

  $("mintBtn").addEventListener("click", openMint);

  // Esc closes overlays
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (!$("modal").hidden) closeModal();
      else if (!$("settingsPanel").hidden) closeSettings();
    }
  });

  function refreshCurrentView() {
    if (current === "enroll") loadEnroll();
    else if (current === "identities") loadUsers();
    else if (current === "revocation") loadCRL();
    else if (current === "vault") loadVault();
  }

  /* ========================================================================
     VISIBILITY: pause polling when hidden, resume on return
     ===================================================================== */
  document.addEventListener("visibilitychange", () => {
    visible = !document.hidden;
    if (visible) {
      setLive(current === "enroll");
      refreshOverview();
      if (current === "enroll") startEnrollPoll();
      else refreshCurrentView();
    } else {
      stopEnrollPoll();
      setLive(false);
    }
  });

  /* ========================================================================
     BOOT
     ===================================================================== */
  function init() {
    wireRevokeToken();
    wireRevokeGrant();
    wireVaultForm();
    refreshOverview();
    // refresh overview stats periodically too (keeps the pending badge live across tabs)
    setInterval(() => { if (visible && current !== "enroll") loadPendingCount(); }, POLL_MS * 2);
    show("overview");
  }
  init();
})();
