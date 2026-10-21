/* Nullink Files favorites (fav1): pinned folders on the Nullink Files and Server drives.
   Stored server-side (/api/fm/favorites, owner-only). Opening a Server favorite goes through
   the Server drive, so its 15-minute unlock still applies. Plain JS, no framework. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const hosts = [$("fav-list"), $("fav-list-strip")].filter(Boolean);
  const section = $("fav-section"), strip = $("fav-strip");
  const NL = () => window.NL || {};
  let items = [];
  let loaded = false;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const find = (drive, path) => items.find((i) => i.drive === drive && i.path === path);

  async function api(url, json) {
    const o = { credentials: "include" };
    if (json !== undefined) { o.method = "POST"; o.headers = { "Content-Type": "application/json" }; o.body = JSON.stringify(json); }
    const r = await fetch(url, o);
    if (r.status === 401 && NL().showAuth) NL().showAuth();
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.message || d.error || `HTTP ${r.status}`);
    return d;
  }
  function note(msg) { const s = $("fav-status"); if (s) { s.textContent = msg || ""; if (msg) setTimeout(() => { if (s.textContent === msg) s.textContent = ""; }, 4000); } }
  function set(next) {
    items = next || [];
    render();
    window.NLFiles && window.NLFiles.rerender();
    window.NLServerDrive && window.NLServerDrive.rerender && window.NLServerDrive.rerender();
  }
  async function load() {
    try { const d = await api("/api/fm/favorites"); loaded = true; set(d.items); } catch { /* signed out or guest */ }
  }

  function star(drive, path) {
    const on = !!find(drive, path);
    const b = el("button", "fav-star" + (on ? " is-on" : ""), on ? "★" : "☆");
    b.type = "button";
    b.title = on ? "Remove from Favorites" : "Add to Favorites";
    b.setAttribute("aria-pressed", String(on));
    b.setAttribute("aria-label", b.title);
    b.addEventListener("click", async (e) => {
      e.stopPropagation();
      try {
        const cur = find(drive, path);
        const d = cur ? await api("/api/fm/favorites/remove", { id: cur.id }) : await api("/api/fm/favorites/add", { drive, path });
        set(d.items);
        note(cur ? "Removed from Favorites." : "Added to Favorites.");
      } catch (err) { note(err.message === "drive_locked" ? "Unlock the Server drive first." : err.message); }
    });
    return b;
  }

  function open(it) {
    if (NL().setMode) NL().setMode("files");
    if (it.drive === "server") { window.NLServerDrive && window.NLServerDrive.open(it.path); return; }
    if (it.drive === "github") { window.NLGitHub && window.NLGitHub.open(it.path); return; }
    window.NLServerDrive && window.NLServerDrive.pick("files");
    window.NLFiles && window.NLFiles.go(it.path);
  }
  async function rename(it) {
    const label = prompt("Rename favorite", it.label);
    if (label == null || !label.trim()) return;
    try { set((await api("/api/fm/favorites/rename", { id: it.id, label })).items); } catch (e) { note(e.message); }
  }
  async function remove(it) {
    try { set((await api("/api/fm/favorites/remove", { id: it.id })).items); } catch (e) { note(e.message); }
  }
  async function reorder(ids) {
    const prev = items;
    const by = Object.fromEntries(items.map((i) => [i.id, i]));
    items = ids.map((id) => by[id]); render();
    try { set((await api("/api/fm/favorites/reorder", { ids })).items); } catch (e) { items = prev; render(); note(e.message); }
  }

  // Drag to reorder: HTML5 DnD on desktop, pointer drag on the handle for touch (Pixel).
  let dragId = null;
  function render() {
    if (section) section.hidden = !loaded;
    if (strip) strip.hidden = !loaded;
    document.querySelectorAll(".fav-empty").forEach((n) => { n.hidden = items.length > 0; });
    hosts.forEach(renderInto);
  }
  function renderInto(host) {
    host.textContent = "";
    items.forEach((it) => {
      const li = el("li", "fav-item");
      li.dataset.id = it.id;
      li.draggable = true;
      const handle = el("span", "fav-handle", "⋮⋮");
      handle.title = "Drag to reorder";
      const b = el("button", "fav-open", (it.drive === "server" ? "🖥 " : it.drive === "github" ? "🐙 " : "📁 ") + it.label);
      b.type = "button";
      b.title = (it.drive === "server" ? "Server " : it.drive === "github" ? "GitHub " : "Files /") + it.path;
      b.addEventListener("click", () => open(it));
      const rn = el("button", "ghost tiny fav-act", "✎"); rn.type = "button"; rn.title = "Rename"; rn.setAttribute("aria-label", "Rename " + it.label);
      rn.addEventListener("click", () => rename(it));
      const rm = el("button", "ghost tiny fav-act", "✕"); rm.type = "button"; rm.title = "Remove"; rm.setAttribute("aria-label", "Remove " + it.label);
      rm.addEventListener("click", () => remove(it));
      li.append(handle, b, rn, rm);
      li.addEventListener("dragstart", (e) => { dragId = it.id; li.classList.add("is-drag"); e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/x-nl-fav", it.id); });
      li.addEventListener("dragend", () => { dragId = null; li.classList.remove("is-drag"); });
      li.addEventListener("dragover", (e) => { if (dragId) { e.preventDefault(); e.stopPropagation(); } });
      li.addEventListener("drop", (e) => { if (!dragId) return; e.preventDefault(); e.stopPropagation(); dropOn(it.id); });
      handle.addEventListener("pointerdown", (e) => touchDrag(e, li, it.id, host));
      host.appendChild(li);
    });
  }
  function dropOn(targetId) {
    if (!dragId || dragId === targetId) return;
    const ids = items.map((i) => i.id).filter((id) => id !== dragId);
    const from = items.findIndex((i) => i.id === dragId), to = items.findIndex((i) => i.id === targetId);
    ids.splice(ids.indexOf(targetId) + (from < to ? 1 : 0), 0, dragId);
    dragId = null;
    reorder(ids);
  }
  function touchDrag(e, li, id, host) {
    if (e.pointerType === "mouse") return;
    e.preventDefault();
    li.classList.add("is-drag");
    const move = (ev) => {
      const over = document.elementFromPoint(ev.clientX, ev.clientY);
      const target = over && over.closest(".fav-item");
      host.querySelectorAll(".fav-item").forEach((n) => n.classList.toggle("is-over", n === target && n !== li));
    };
    const up = (ev) => {
      window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up);
      li.classList.remove("is-drag");
      const over = document.elementFromPoint(ev.clientX, ev.clientY);
      const target = over && over.closest(".fav-item");
      host.querySelectorAll(".is-over").forEach((n) => n.classList.remove("is-over"));
      if (target && target.dataset.id !== id) { dragId = id; dropOn(target.dataset.id); }
    };
    window.addEventListener("pointermove", move); window.addEventListener("pointerup", up);
  }

  window.NLFav = { star, reload: load, items: () => items.slice() };
  load();
  document.addEventListener("nl:files-loaded", () => { if (!loaded) load(); });
})();
