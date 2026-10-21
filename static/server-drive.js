/* Nullink Server drive (sd1): browse "/" as the Nullink service user. Locked until a fresh
   authenticator code (15 min, enforced server-side). Writes go through NL.stepUpFetch.
   Plain JS, no framework. Talks to /api/sd/*. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const sd = $("sd"), fm = $("fm"), sw = $("drive-switch");
  if (!sd || !fm || !sw) return;
  const NL = () => window.NL || {};
  const els = { locked: $("sd-locked"), open: $("sd-open"), form: $("sd-unlock-form"), code: $("sd-code"),
    crumbs: $("sd-crumbs"), list: $("sd-list"), empty: $("sd-empty"), status: $("sd-status"),
    timer: $("sd-timer"), upload: $("sd-upload-input"), mk: $("sd-new-folder"), lock: $("sd-lock"),
    dlg: $("fm-dialog"), dlgTitle: $("fm-dialog-title"), dlgBody: $("fm-dialog-body"), dlgFoot: $("fm-dialog-foot") };
  const state = { cwd: "/", left: 0, tick: null };
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const join = (d, n) => (d === "/" ? "/" + n : d + "/" + n);
  const q = (p) => encodeURIComponent(p);
  function status(m, err) { els.status.textContent = m || ""; els.status.classList.toggle("fm-status--err", !!err); }
  function size(n) { if (n == null) return ""; if (n < 1024) return n + " B"; if (n < 1048576) return (n / 1024).toFixed(1) + " KB"; return (n / 1048576).toFixed(1) + " MB"; }

  async function api(url, opts = {}, stepUp = false) {
    const o = Object.assign({ credentials: "include" }, opts);
    if (o.json !== undefined) { o.method = "POST"; o.headers = { "Content-Type": "application/json" }; o.body = JSON.stringify(o.json); delete o.json; }
    const r = stepUp && NL().stepUpFetch ? await NL().stepUpFetch(url, o) : await fetch(url, o);
    if (r.status === 401 && NL().showAuth) NL().showAuth();
    const d = await r.json().catch(() => ({}));
    if (d.error === "drive_locked") { showLocked(); }
    if (!r.ok) throw new Error(d.message || d.error || `HTTP ${r.status}`);
    return d;
  }

  function pick(drive) {
    const server = drive === "server";
    sw.querySelectorAll(".drive-tab").forEach((b) => { const on = b.dataset.drive === drive; b.classList.toggle("is-active", on); b.setAttribute("aria-selected", on); });
    sd.hidden = !server; fm.hidden = server;
    if (server) init();
  }
  sw.addEventListener("click", (e) => { const b = e.target.closest(".drive-tab"); if (b) pick(b.dataset.drive); });

  function showLocked() { els.locked.hidden = false; els.open.hidden = true; clearInterval(state.tick); setTimeout(() => els.code.focus(), 0); }
  function startTimer(sec) {
    state.left = sec; clearInterval(state.tick);
    const paint = () => { const m = Math.floor(state.left / 60), s = state.left % 60; els.timer.textContent = `Locks in ${m}:${String(s).padStart(2, "0")}`; };
    paint();
    state.tick = setInterval(() => { state.left -= 1; if (state.left <= 0) { showLocked(); status("Server drive locked again."); } else paint(); }, 1000);
  }
  async function init() {
    try {
      const s = await api("/api/sd/status");
      if (!s.unlocked) return showLocked();
      els.locked.hidden = true; els.open.hidden = false; startTimer(s.unlocked_for_sec); load(state.cwd);
    } catch (e) { status(e.message, true); }
  }
  els.form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try { await api("/api/sd/unlock", { json: { code: els.code.value.trim() } }); els.code.value = ""; status(""); init(); }
    catch (err) { status(err.message === "wrong_code" ? "Incorrect code." : err.message, true); }
  });
  els.lock.addEventListener("click", async () => { await api("/api/sd/lock", { json: {} }).catch(() => {}); showLocked(); });

  function crumbs(p) {
    els.crumbs.textContent = "";
    const parts = p.split("/").filter(Boolean);
    const add = (label, path, cur) => { const b = el("button", "fm-crumb" + (cur ? " fm-crumb--cur" : ""), label); b.type = "button"; b.onclick = () => load(path); els.crumbs.appendChild(b); };
    add("Server /", "/", !parts.length);
    let acc = "";
    parts.forEach((seg, i) => { acc += "/" + seg; els.crumbs.appendChild(el("span", "fm-crumb-sep", "/")); add(seg, acc, i === parts.length - 1); });
  }
  async function load(p) {
    try {
      const d = await api(`/api/sd/list?path=${q(p)}`);
      state.cwd = d.path; crumbs(d.path); render(d.items, d.truncated);
      if (window.NLFav) els.crumbs.appendChild(window.NLFav.star("server", d.path));
    } catch (e) { status(e.message === "permission_denied" ? "The Nullink service user can't open that folder." : e.message, true); }
  }
  function render(items, truncated) {
    els.list.textContent = "";
    els.empty.hidden = items.length > 0;
    if (state.cwd !== "/") {
      const li = el("li", "sd-row"); const b = el("button", "sd-name", "⬑ ..");
      b.type = "button"; b.onclick = () => load(state.cwd.replace(/\/[^/]+$/, "") || "/"); li.appendChild(b); els.list.appendChild(li);
    }
    for (const it of items) {
      const li = el("li", "sd-row" + (it.masked ? " is-masked" : "") + (it.kind === "symlink" ? " is-link" : ""));
      const icon = it.masked ? "🔒 " : it.kind === "dir" ? "📁 " : it.kind === "symlink" ? "↪ " : "📄 ";
      const b = el("button", "sd-name", icon + it.name); b.type = "button";
      if (it.masked) b.title = "Hidden: secrets, env or token file";
      else if (it.kind === "symlink") b.title = "Symlinks are not followed";
      else if (it.kind === "dir") b.onclick = () => load(it.path);
      else if (it.kind === "file") b.onclick = () => preview(it);
      li.appendChild(b);
      li.appendChild(el("span", "sd-meta sd-mode", it.masked ? "" : it.mode || ""));
      li.appendChild(el("span", "sd-meta sd-date", it.kind === "file" ? size(it.size) : ""));
      const acts = el("span", "sd-acts");
      if (!it.masked && it.kind === "dir" && window.NLFav) acts.appendChild(window.NLFav.star("server", it.path));
      if (!it.masked) {
        if (it.kind === "file") { const dl = el("a", "ghost tiny", "⬇"); dl.href = `/api/sd/download?path=${q(it.path)}`; dl.title = "Download"; acts.appendChild(dl); }
        const mv = el("button", "ghost tiny", "✎"); mv.type = "button"; mv.title = "Rename"; mv.onclick = () => rename(it); acts.appendChild(mv);
        const del = el("button", "ghost tiny fm-danger", "🗑"); del.type = "button"; del.title = "Delete permanently"; del.onclick = () => remove(it); acts.appendChild(del);
      }
      li.appendChild(acts);
      els.list.appendChild(li);
    }
    if (truncated) els.list.appendChild(el("li", "hint", "Showing the first 5000 entries."));
  }
  function dialog(title, body, buttons) {
    els.dlgTitle.textContent = title; els.dlgBody.textContent = ""; els.dlgFoot.textContent = "";
    els.dlgBody.appendChild(body);
    for (const [label, cls, fn] of buttons) { const b = el("button", cls, label); b.type = "button"; b.onclick = () => fn(); els.dlgFoot.appendChild(b); }
    if (!els.dlg.open) els.dlg.showModal();
  }
  async function preview(it) {
    const img = /\.(png|jpe?g|gif|webp|bmp)$/i.test(it.name);
    try {
      let body;
      if (img) {
        const r = await fetch(`/api/sd/preview?path=${q(it.path)}`, { credentials: "include" });
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
        body = el("img", "sd-preview-img"); body.src = URL.createObjectURL(await r.blob()); body.alt = it.name;
      } else {
        const d = await api(`/api/sd/preview?path=${q(it.path)}`);
        body = el("pre", "sd-preview", d.text + (d.truncated ? "\n… (first 256 KB)" : ""));
      }
      dialog(it.path, body, [["Download", "ghost tiny", () => { location.href = `/api/sd/download?path=${q(it.path)}`; }], ["Close", "accent-btn tiny", () => els.dlg.close()]]);
    } catch (e) { status(e.message === "not_previewable" ? "No preview for this type. Use Download." : e.message, true); }
  }
  function rename(it) {
    const inp = el("input"); inp.value = it.name; inp.className = "fm-input";
    dialog("Rename", inp, [["Cancel", "ghost tiny", () => els.dlg.close()], ["Rename", "accent-btn tiny", async () => {
      try { await api("/api/sd/rename", { json: { path: it.path, name: inp.value.trim() } }, true); els.dlg.close(); load(state.cwd); }
      catch (e) { status(e.message, true); }
    }]]);
  }
  function remove(it) {
    const wrap = el("div");
    wrap.appendChild(el("p", "", `Delete ${it.path} permanently? The Server drive has no Trash.${it.kind === "dir" ? " Only empty folders can be deleted." : ""}`));
    wrap.appendChild(el("p", "hint", `Type ${it.name} to confirm.`));
    const inp = el("input"); inp.className = "fm-input"; inp.autocomplete = "off"; wrap.appendChild(inp);
    dialog("Delete permanently", wrap, [["Cancel", "ghost tiny", () => els.dlg.close()], ["Delete forever", "accent-btn tiny fm-danger", async () => {
      try { await api("/api/sd/delete", { json: { path: it.path, confirm: inp.value } }, true); els.dlg.close(); status(`Deleted ${it.name}.`); load(state.cwd); }
      catch (e) { status(e.message === "confirm_mismatch" ? "The name didn't match." : e.message, true); }
    }]]);
  }
  els.mk.addEventListener("click", () => {
    const inp = el("input"); inp.className = "fm-input"; inp.placeholder = "Folder name";
    dialog("New folder in " + state.cwd, inp, [["Cancel", "ghost tiny", () => els.dlg.close()], ["Create", "accent-btn tiny", async () => {
      try { await api("/api/sd/mkdir", { json: { path: state.cwd, name: inp.value.trim() } }, true); els.dlg.close(); load(state.cwd); }
      catch (e) { status(e.message, true); }
    }]]);
  });
  els.upload.addEventListener("change", async () => {
    const f = els.upload.files[0]; els.upload.value = "";
    if (!f) return;
    try { await api(`/api/sd/upload?path=${q(state.cwd)}&name=${q(f.name)}`, { method: "POST", body: f }, true); status(`Uploaded ${f.name}.`); load(state.cwd); }
    catch (e) { status(e.message, true); }
  });
  function openPath(p) { state.cwd = p || "/"; pick("server"); }
  window.NLServerDrive = { pick, open: openPath, rerender: () => { if (!els.open.hidden) load(state.cwd); } };
})();
