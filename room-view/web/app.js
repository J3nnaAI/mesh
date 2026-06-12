/* ============================================================================
   Mesh Room — human chat client (vanilla JS, no dependencies)

   Drives the same-origin room-view API:
     GET  /api/state             — who/where we are + roster + peers
     GET  /api/messages?since=N  — incremental room history (seq monotonic)
     POST /api/post {text}       — post as this person

   Principles:
   - All server-supplied strings (text, aliases, node ids) are rendered with
     textContent / DOM nodes only — never innerHTML. Room content is untrusted.
   - `since` tracks the max seq across EVERY message (including skipped system
     kinds) so we never re-pull the same events forever.
   - Resilient: any non-200 / network error holds last-good state and shows a
     calm inline state, never a broken page. Polling pauses on a hidden tab.
   ============================================================================ */
(function () {
  "use strict";

  // ── Element handles ──────────────────────────────────────────────────────
  var $ = function (id) { return document.getElementById(id); };
  var room = $("room");
  var roomName = $("roomName");
  var selfAlias = $("selfAlias");
  var transcript = $("transcript");
  var feed = $("feed");
  var connecting = $("connecting");
  var empty = $("empty");
  var form = $("composerForm");
  var input = $("input");
  var send = $("send");
  var toast = $("toast");
  var newpill = $("newpill");
  var presence = $("presence");
  var presenceToggle = $("presenceToggle");
  var presenceCount = $("presenceCount");
  var rosterList = $("rosterList");

  // ── State ────────────────────────────────────────────────────────────────
  var sinceSeq = 0;                 // high-water mark across ALL message kinds
  var seen = Object.create(null);   // seq -> true (guard against dupes)
  var joined = false;
  var selfId = "";
  var aliasByNode = Object.create(null);  // node_id -> alias
  var agentNodes = Object.create(null);   // node_id -> true (best-effort)
  var humanNodes = Object.create(null);   // node_id -> true (best-effort)
  var lastSenderKey = null;               // for visual grouping of runs
  var hasRenderedMessage = false;
  var msgTimer = null, stateTimer = null, toastTimer = null;

  var MSG_INTERVAL = 1500;
  var STATE_INTERVAL = 3000;

  // System / non-chat kinds. "say" is a normal chat post.
  // join/leave become subtle system lines; everything else (roster, approved,
  // tool_* …) is skipped from display but still advances the seq watermark.
  function isChat(kind) { return kind === "say" || kind === "chat" || kind === "" || kind == null; }

  // ── Helpers ────────────────────────────────────────────────────────────
  function shortId(id) {
    if (!id) return "node";
    return String(id).slice(0, 8);
  }

  function aliasFor(nodeId) {
    if (nodeId && aliasByNode[nodeId]) return aliasByNode[nodeId];
    return shortId(nodeId);
  }

  function isAtBottom() {
    // within ~80px of the bottom counts as "following along"
    return transcript.scrollHeight - transcript.scrollTop - transcript.clientHeight < 80;
  }

  function scrollToBottom() {
    transcript.scrollTop = transcript.scrollHeight;
    hideNewPill();
  }

  function showNewPill() { newpill.hidden = false; }
  function hideNewPill() { newpill.hidden = true; }

  function showToast(text) {
    toast.textContent = text;
    toast.hidden = false;
    // force reflow so the transition runs on re-show
    void toast.offsetWidth;
    toast.classList.add("toast--show");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      toast.classList.remove("toast--show");
      toastTimer = setTimeout(function () { toast.hidden = true; }, 240);
    }, 3600);
  }

  // ── Rendering ────────────────────────────────────────────────────────────
  function setState(name) {
    room.setAttribute("data-state", name);
  }

  function refreshScreens() {
    if (!joined) {
      connecting.hidden = false;
      empty.hidden = true;
      feed.hidden = true;
      setState("connecting");
      return;
    }
    setState("joined");
    connecting.hidden = true;
    if (hasRenderedMessage) {
      empty.hidden = true;
      feed.hidden = false;
    } else {
      empty.hidden = false;
      feed.hidden = true;
    }
  }

  // Build one chat message element entirely from DOM nodes (no innerHTML).
  function chatNode(msg, opts) {
    var li = document.createElement("li");
    li.className = "msg";
    li.setAttribute("data-from", msg.from || "");

    var meta = document.createElement("div");
    meta.className = "msg__meta";
    var alias = document.createElement("span");
    alias.className = "msg__alias";
    meta.appendChild(alias);
    var chip = document.createElement("span");
    chip.className = "msg__chip";
    chip.textContent = shortId(msg.from);
    meta.appendChild(chip);
    li.appendChild(meta);

    var bubble = document.createElement("div");
    bubble.className = "bubble msg__bubble";
    bubble.textContent = msg.text != null ? String(msg.text) : "";
    li.appendChild(bubble);

    if (opts && opts.grouped) li.classList.add("msg--grouped");
    if (opts && opts.enter) li.classList.add("msg--enter");

    // Identity (mine / agent / alias) is resolved here AND re-resolved later
    // when state arrives, so messages that rendered before we knew the roster
    // or our own id get corrected in place (no stale short-id fallbacks).
    resolveIdentity(li);
    return li;
  }

  // (Re)apply self-alignment, agent tone, and alias text to a chat <li> from
  // current state. Safe to call repeatedly; idempotent.
  function resolveIdentity(li) {
    var from = li.getAttribute("data-from") || "";
    var mine = from && from === selfId;
    var agent = !mine && agentNodes[from] && !humanNodes[from];
    li.classList.toggle("msg--me", !!mine);
    li.classList.toggle("msg--agent", !!agent);
    var alias = li.querySelector(".msg__alias");
    if (alias) alias.textContent = aliasFor(from);
  }

  function reconcileIdentities() {
    var nodes = feed.querySelectorAll(".msg");
    for (var i = 0; i < nodes.length; i++) resolveIdentity(nodes[i]);
  }

  // A subtle centered system line (joins / leaves).
  function sysNode(text, enter) {
    var li = document.createElement("li");
    li.className = "sysline";
    if (enter) li.classList.add("msg--enter");
    li.textContent = text;
    return li;
  }

  function senderKeyFor(msg) {
    return (msg.from === selfId ? "me:" : "peer:") + (msg.from || "");
  }

  // Append one server message to the feed; returns true if something visible
  // was rendered. `live` enables the enter animation + grouping reset rules.
  function renderMessage(msg, live) {
    if (isChat(msg.kind)) {
      var key = senderKeyFor(msg);
      var grouped = key === lastSenderKey;
      lastSenderKey = key;
      feed.appendChild(chatNode(msg, { grouped: grouped, enter: live }));
      hasRenderedMessage = true;
      return true;
    }
    // presence system lines
    if (msg.kind === "join") {
      lastSenderKey = null;
      var who = msg.text ? String(msg.text) : aliasFor(msg.from);
      var li = sysNode("", live);
      var b = document.createElement("b");
      b.textContent = who;
      li.appendChild(b);
      li.appendChild(document.createTextNode(" joined the room"));
      feed.appendChild(li);
      return true;
    }
    if (msg.kind === "leave") {
      lastSenderKey = null;
      var who2 = aliasFor(msg.from);
      var li2 = sysNode("", live);
      var b2 = document.createElement("b");
      b2.textContent = who2;
      li2.appendChild(b2);
      li2.appendChild(document.createTextNode(" left the room"));
      feed.appendChild(li2);
      return true;
    }
    // roster / approved / tool_* / unknown — not shown, but seq still advances
    return false;
  }

  // ── Polling ────────────────────────────────────────────────────────────
  function pollMessages() {
    fetch("/api/messages?since=" + sinceSeq, { headers: { Accept: "application/json" } })
      .then(function (r) {
        if (!r.ok) throw new Error("status " + r.status);
        return r.json();
      })
      .then(function (data) {
        var wasJoined = joined;
        if (typeof data.joined === "boolean") joined = data.joined;
        var msgs = Array.isArray(data.messages) ? data.messages : [];

        var stick = isAtBottom();
        var renderedVisible = false;
        var live = wasJoined; // first load (was not joined) renders without animation

        for (var i = 0; i < msgs.length; i++) {
          var m = msgs[i];
          var seq = typeof m.seq === "number" ? m.seq : null;
          if (seq != null) {
            if (seen[seq]) continue;
            seen[seq] = true;
            if (seq > sinceSeq) sinceSeq = seq; // advance across EVERY kind
          }
          if (renderMessage(m, live)) renderedVisible = true;
        }

        if (joined !== wasJoined) refreshScreens();
        else if (renderedVisible) refreshScreens();

        if (renderedVisible) {
          if (stick) scrollToBottom();
          else showNewPill();
        }
      })
      .catch(function () {
        // Transient (502 while joined, network blip) — hold last-good state.
      });
  }

  function pollState() {
    fetch("/api/state", { headers: { Accept: "application/json" } })
      .then(function (r) {
        if (!r.ok) throw new Error("status " + r.status);
        return r.json();
      })
      .then(function (data) {
        if (data.room) roomName.textContent = String(data.room);
        if (data.alias) selfAlias.textContent = String(data.alias);
        if (data.self_id) selfId = String(data.self_id);
        if (typeof data.joined === "boolean" && data.joined !== joined) {
          joined = data.joined;
          refreshScreens();
        }

        // Caps live on peers, keyed by node id. A peer with the "human" cap is
        // a person; one advertising "rooms"/other caps is treated as an agent.
        agentNodes = Object.create(null);
        humanNodes = Object.create(null);
        var peers = Array.isArray(data.peers) ? data.peers : [];
        for (var p = 0; p < peers.length; p++) {
          var caps = Array.isArray(peers[p].caps) ? peers[p].caps : [];
          var human = caps.indexOf("human") !== -1;
          if (human) humanNodes[peers[p].id] = true;
          else if (caps.length) agentNodes[peers[p].id] = true;
        }

        // Roster: alias map + presence list.
        aliasByNode = Object.create(null);
        var roster = Array.isArray(data.roster) ? data.roster : [];
        for (var k = 0; k < roster.length; k++) {
          var mem = roster[k];
          if (mem && mem.node_id) aliasByNode[mem.node_id] = mem.alias || shortId(mem.node_id);
        }
        renderRoster(roster);
        // Correct any messages that rendered before this state arrived.
        reconcileIdentities();
      })
      .catch(function () { /* hold last-good roster + state */ });
  }

  function renderRoster(roster) {
    presenceCount.textContent = String(roster.length);
    var frag = document.createDocumentFragment();
    for (var i = 0; i < roster.length; i++) {
      var mem = roster[i];
      if (!mem) continue;
      var id = mem.node_id || "";
      var li = document.createElement("li");
      li.className = "member";

      var isMe = id && id === selfId;
      var isHuman = isMe || humanNodes[id];
      var isAgent = !isHuman && agentNodes[id];
      if (isHuman) li.classList.add("member--human");
      if (isAgent) li.classList.add("member--agent");
      if (isMe) li.classList.add("member--you");

      var dot = document.createElement("span");
      dot.className = "member__dot";
      dot.setAttribute("aria-hidden", "true");
      li.appendChild(dot);

      var name = document.createElement("span");
      name.className = "member__name";
      name.textContent = mem.alias || shortId(id);
      li.appendChild(name);

      // Only label what we actually know; degrade to neutral otherwise.
      var tagText = isMe ? "you" : (isHuman ? "person" : (isAgent ? "agent" : ""));
      if (tagText) {
        var tag = document.createElement("span");
        tag.className = "member__tag";
        tag.textContent = tagText;
        li.appendChild(tag);
      }
      frag.appendChild(li);
    }
    rosterList.textContent = "";
    rosterList.appendChild(frag);
  }

  // ── Composer ─────────────────────────────────────────────────────────────
  function autosize() {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, window.innerHeight * 0.4) + "px";
  }

  function submit() {
    var text = input.value.replace(/\s+$/, "");
    if (!text.trim()) return;

    send.disabled = true;
    fetch("/api/post", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text })
    })
      .then(function (r) {
        if (r.ok) return r.json().then(function () { return { ok: true }; });
        // Read the server's text body for a meaningful message.
        return r.text().then(function (body) {
          return { ok: false, status: r.status, body: body };
        });
      })
      .then(function (res) {
        send.disabled = false;
        if (res.ok) {
          input.value = "";
          autosize();
          input.focus();
          pollMessages(); // pull our message right away
        } else {
          // Keep the typed text; just tell them gently and re-enable.
          var msg = res.status === 503
            ? "Still finding the room — your message wasn't sent yet."
            : (res.body && res.body.trim()) ? res.body.trim() : "Couldn't send. Try again.";
          showToast(msg);
        }
      })
      .catch(function () {
        send.disabled = false;
        showToast("Network hiccup — your message wasn't sent. Try again.");
      });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    submit();
  });

  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  });
  input.addEventListener("input", autosize);

  // ── Presence toggle (mobile drawer; permanent rail on wide screens) ──────
  presenceToggle.addEventListener("click", function () {
    var open = presence.hidden;
    presence.hidden = !open;
    presenceToggle.setAttribute("aria-expanded", open ? "true" : "false");
  });

  // ── New-messages pill ────────────────────────────────────────────────────
  newpill.addEventListener("click", scrollToBottom);
  newpill.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); scrollToBottom(); }
  });
  transcript.addEventListener("scroll", function () {
    if (isAtBottom()) hideNewPill();
  });

  // ── Polling lifecycle (pause on hidden tab) ──────────────────────────────
  function startPolling() {
    if (msgTimer == null) {
      pollMessages();
      msgTimer = setInterval(pollMessages, MSG_INTERVAL);
    }
    if (stateTimer == null) {
      pollState();
      stateTimer = setInterval(pollState, STATE_INTERVAL);
    }
  }
  function stopPolling() {
    if (msgTimer != null) { clearInterval(msgTimer); msgTimer = null; }
    if (stateTimer != null) { clearInterval(stateTimer); stateTimer = null; }
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) stopPolling();
    else startPolling();
  });

  // ── Boot ─────────────────────────────────────────────────────────────────
  refreshScreens();
  startPolling();
})();
