// Nullink guest access: request (sign-in page), owner panel, guest countdown.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const post = (url, body) => fetch(url, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const fmtLeft = (sec) => { sec = Math.max(0, Math.round(sec)); return Math.floor(sec / 60) + ":" + String(sec % 60).padStart(2, "0"); };

  // ---- sign-in page: request + redeem ----
  const reqBtn = $("guest-request-btn"), reqBox = $("guest-request-box");
  if (reqBtn) reqBtn.addEventListener("click", () => reqBox.classList.toggle("hidden"));
  const send = $("guest-request-send");
  if (send) send.addEventListener("click", async () => {
    const out = $("guest-request-status");
    out.textContent = "Sending\u2026";
    try {
      const r = await post("/api/guest/request", { name: $("guest-name").value, reason: $("guest-reason").value });
      const d = await r.json();
      if (!r.ok) { out.textContent = d.message || "Request failed."; return; }
      send.textContent = "Sent \u2713"; send.disabled = true; send.classList.add("sent");
      out.innerHTML = "Request <strong>" + esc(d.request_id) + "</strong> sent \u2014 waiting for owner. When approved, enter the guest PIN below (valid 60 seconds).";
      const poll = setInterval(async () => {
        const s = await fetch("/api/guest/request/" + d.request_id + "?poll=" + encodeURIComponent(d.poll_token)).then((x) => x.json()).catch(() => ({}));
        if (s.status && s.status !== "pending") {
          clearInterval(poll);
          out.innerHTML = "Request <strong>" + esc(d.request_id) + "</strong>: " + esc(s.status === "approved" ? "approved \u2014 enter the guest PIN the owner gives you" : s.status);
        }
      }, 5000);
    } catch { out.textContent = "Network error."; }
  });
  const redeem = $("guest-redeem-send");
  if (redeem) redeem.addEventListener("click", async () => {
    const out = $("guest-redeem-error");
    const r = await post("/api/auth/guest/redeem", { pin: $("guest-pin").value.trim() });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { out.textContent = d.message || "Invalid guest PIN."; return; }
    location.reload();
  });

  // ---- signed in: owner panel or guest banner ----
  let me = null;
  async function loadMe() {
    try { me = await fetch("/api/me", { credentials: "include" }).then((r) => r.json()); } catch { me = null; }
    return me;
  }

  const banner = $("guest-banner");
  function guestTick() {
    if (!me || me.auth_type !== "guest") return;
    const g = me.guest || {};
    const left = g.expires_at - (g.now || Date.now() / 1000) - (Date.now() / 1000 - me._t);
    banner.classList.remove("hidden");
    banner.textContent = "Guest session (" + (g.scope === "full" ? "full" : "read-only") + ") \u00b7 " + fmtLeft(left) + " left" +
      (left <= 60 ? " \u00b7 waiting for owner to extend\u2026" : "");
    if (left <= 0) location.reload();
  }
  // ---- guest-mode UI: read-only controls, blocked-write toast, hidden history ----
  const RO_TIP = "Read-only guest session";
  function toast(msg) {
    let t = $("guest-toast");
    if (!t) { t = document.createElement("div"); t.id = "guest-toast"; t.className = "guest-toast"; t.setAttribute("role", "status"); document.body.appendChild(t); }
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast._h); toast._h = setTimeout(() => { t.hidden = true; }, 3500);
  }
  let lastCompose = "";
  function installGuestFetch() {
    const orig = window.fetch.bind(window);
    window.fetch = async (url, opts) => {
      const method = String((opts && opts.method) || "GET").toUpperCase();
      const r = await orig(url, opts);
      if (r.status === 403 && method !== "GET") {
        toast("Read-only guest session \u2014 action blocked");
        const ci = $("compose-input");
        if (ci && lastCompose && !ci.value) ci.value = lastCompose;
      }
      return r;
    };
    const form = $("compose");
    if (form) form.addEventListener("submit", () => { const ci = $("compose-input"); lastCompose = ci ? ci.value : ""; }, true);
  }
  function applyReadOnly() {
    const sel = "#compose-input, #send-btn, #new-label-name, #vault-new-btn, #sm-goal, #sm-last-decision, #sm-blockers, #sm-notes, #upload-input";
    document.querySelectorAll(sel).forEach((el) => {
      el.disabled = true; el.title = RO_TIP; el.classList.add("guest-ro-disabled");
      if (el.id === "compose-input") el.placeholder = RO_TIP;
    });
  }
  function hideHistory() {
    const m = $("messages");
    if (m && !(m.childElementCount === 1 && m.firstElementChild.classList.contains("guest-history-hidden"))) {
      m.innerHTML = "<p class='guest-history-hidden'>Chat history hidden for guests</p>";
    }
  }
  async function guestRefresh() { await loadMe(); if (me) me._t = Date.now() / 1000; }

  const accessBtn = $("guest-access-btn"), modal = $("guest-modal"), list = $("guest-list");
  async function ownerRefresh() {
    const r = await fetch("/api/guest/requests", { credentials: "include" });
    if (!r.ok) return;
    const d = await r.json();
    const soon = d.sessions.filter((s) => s.expiring_soon).length;
    const n = d.pending.length + soon;
    accessBtn.textContent = "Guest access" + (n ? " (" + n + ")" : "");
    accessBtn.classList.toggle("guest-alert", n > 0);
    if (modal.classList.contains("hidden")) return;
    let h = "<h3>Pending requests</h3>";
    if (!d.pending.length) h += "<p class='hint'>None.</p>";
    d.pending.forEach((q) => {
      h += "<div class='guest-row'><strong>" + esc(q.id) + "</strong> " + esc(q.name || "(no name)") + "<br><span class='hint'>" + esc(q.reason) + " \u00b7 " + esc(q.ip) + "</span><br>" +
        "<select data-scope='" + q.id + "'><option value='read'>Read-only view</option><option value='full'>Full</option></select> " +
        "<button class='accent-btn' data-approve='" + q.id + "'>Approve</button> <button class='ghost' data-deny='" + q.id + "'>Deny</button></div>";
    });
    h += "<h3>Active guest sessions</h3>";
    if (!d.sessions.length) h += "<p class='hint'>None.</p>";
    d.sessions.forEach((s) => {
      h += "<div class='guest-row" + (s.expiring_soon ? " guest-alert" : "") + "'>" + esc(s.guest_name) + " \u00b7 " + esc(s.scope) + " \u00b7 " + esc(s.ip) +
        " \u00b7 ends in " + fmtLeft(s.expires_at - Date.now() / 1000) + (s.expiring_soon ? " <strong>\u2014 ending soon</strong>" : "") + "<br>" +
        "<button class='accent-btn' data-extend='" + s.id + "'>Extend +10 min</button> <button class='ghost' data-end='" + s.id + "'>Close</button></div>";
    });
    if (d.sessions.length) h += "<button class='ghost' id='guest-end-all'>End all guest sessions</button>";
    h += "<h3>Mint a guest PIN</h3><input id='guest-mint-name' placeholder='Name (e.g. Replit AI)'> <select id='guest-mint-scope'><option value='read'>Read-only</option><option value='full'>Full</option></select> <button class='ghost' id='guest-mint'>Mint</button>";
    list.innerHTML = h;
  }
  // Persistent PIN card: lives on <body>, so modal re-renders/polling and toasts never hide it.
  let pinTimer = null, pinCanMint = false;
  function copyText(txt) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(txt).then(() => true, () => fallbackCopy(txt));
    return Promise.resolve(fallbackCopy(txt));
  }
  function fallbackCopy(txt) {
    const ta = document.createElement("textarea");
    ta.value = txt; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.top = "-1000px"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select(); ta.setSelectionRange(0, txt.length);
    let ok = false; try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta); return ok;
  }
  function closePin() { clearInterval(pinTimer); pinTimer = null; const c = $("guest-pin-card"); if (c) c.remove(); }
  function showPin(d, opts) {
    closePin();
    const c = document.createElement("div");
    c.id = "guest-pin-card"; c.className = "guest-pin-card"; c.setAttribute("role", "alertdialog"); c.setAttribute("aria-label", "Guest PIN");
    if (!d.pin) {
      c.innerHTML = "<button class='guest-pin-x' aria-label='Dismiss'>\u00d7</button><p>" + esc(d.error || d.message || "Failed") + "</p>";
    } else {
      const exp = Number(d.pin_expires_at) || (Date.now() / 1000 + 60);
      c.innerHTML = "<button class='guest-pin-x' aria-label='Dismiss'>\u00d7</button>" +
        "<div class='hint'>Guest PIN for <strong>" + esc(d.request_id) + "</strong></div>" +
        "<div class='guest-pin-row'><code class='guest-pin guest-pin-big'>" + esc(d.pin) + "</code>" +
        "<button class='accent-btn guest-pin-copy'>Copy</button></div>" +
        "<div class='guest-pin-left' aria-live='polite'></div>" +
        "<div class='hint'>Single use \u00b7 session runs in 10-minute blocks.</div>";
      c.dataset.exp = String(exp);
      c.querySelector(".guest-pin-copy").addEventListener("click", async (e) => {
        const b = e.currentTarget, ok = await copyText(d.pin);
        b.textContent = ok ? "Copied \u2713" : "Select & copy"; b.classList.toggle("copied", !!ok);
        if (!ok) { const r = document.createRange(); r.selectNodeContents(c.querySelector(".guest-pin")); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); }
        setTimeout(() => { if (b.isConnected) { b.textContent = "Copy"; b.classList.remove("copied"); } }, 2000);
      });
      pinCanMint = !!(opts && opts.mint);
      const tick = () => {
        const left = Math.max(0, Math.round(exp - Date.now() / 1000)), el = c.querySelector(".guest-pin-left");
        if (left > 0) { el.textContent = "Expires in " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0"); return; }
        clearInterval(pinTimer); pinTimer = null;
        c.classList.add("expired");
        el.innerHTML = "<strong>Code expired</strong>" + (pinCanMint ? " <button class='ghost guest-pin-new'>New code</button>" : "");
        const cp = c.querySelector(".guest-pin-copy"); if (cp) cp.disabled = true;
        const nb = c.querySelector(".guest-pin-new");
        if (nb) nb.addEventListener("click", async () => {
          const r = await post("/api/guest/mint", opts.mint); showPin(await r.json(), opts); ownerRefresh();
        });
      };
      tick(); pinTimer = setInterval(tick, 1000);
    }
    c.querySelector(".guest-pin-x").addEventListener("click", closePin);
    document.body.appendChild(c);
  }
  window.__guestShowPin = showPin;
  if (list) list.addEventListener("click", async (e) => {
    const t = e.target, a = (k) => t.getAttribute(k);
    let r;
    if (a("data-approve")) {
      const scope = list.querySelector("[data-scope='" + a("data-approve") + "']").value;
      r = await post("/api/guest/requests/" + a("data-approve") + "/approve", { scope });
      const d = await r.json(); showPin(d); return ownerRefresh();
    }
    if (t.id === "guest-mint") {
      const body = { name: $("guest-mint-name").value, scope: $("guest-mint-scope").value };
      r = await post("/api/guest/mint", body);
      const d = await r.json(); showPin(d, { mint: body }); return ownerRefresh();
    }
    if (a("data-deny")) r = await post("/api/guest/requests/" + a("data-deny") + "/deny");
    else if (a("data-extend")) r = await post("/api/guest/sessions/" + a("data-extend") + "/extend");
    else if (a("data-end")) r = await post("/api/guest/sessions/" + a("data-end") + "/end");
    else if (t.id === "guest-end-all") { if (!confirm("End all guest sessions?")) return; r = await post("/api/guest/sessions/end-all"); }
    if (r) ownerRefresh();
  });

  async function init() {
    await loadMe();
    if (!me || !me.authenticated) return setTimeout(init, 5000);
    if (me.auth_type === "guest") {
      me._t = Date.now() / 1000;
      if (accessBtn) accessBtn.classList.add("hidden");
      document.body.classList.add("is-guest");
      installGuestFetch();
      const ro = (me.guest || {}).scope !== "full";
      if (ro) document.body.classList.add("guest-ro");
      const each = () => { if (ro) applyReadOnly(); hideHistory(); };
      each(); setInterval(each, 1000);
      setInterval(guestTick, 1000); setInterval(guestRefresh, 15000); guestTick();
      return;
    }
    if (me.auth_type !== "session" || !accessBtn) return;
    accessBtn.classList.remove("hidden"); const ab = $("guest-audit-btn"); if (ab) ab.classList.remove("hidden");
    accessBtn.addEventListener("click", () => { modal.classList.remove("hidden"); ownerRefresh(); });
    $("guest-close").addEventListener("click", () => modal.classList.add("hidden"));
    modal.addEventListener("click", (e) => { if (e.target === modal) modal.classList.add("hidden"); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") modal.classList.add("hidden"); });
    if (location.hash === "#guest-access") { modal.classList.remove("hidden"); }
    ownerRefresh(); setInterval(ownerRefresh, 10000);
  }
  init();
})();
