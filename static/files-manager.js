/* Nullink Files manager — Slice 1 (folder tree + list, upload, folders, rename, move,
   Trash/restore, download, text/image preview). Plain JS, no framework. Talks to /api/fm/*;
   reuses app.js (window.NL) for the editor, Ask Morc and step-up prompts. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const root = $("fm");
  if (!root) return;
  const panel = $("panel-files");
  const els = {
    crumbs: $("fm-crumbs"), tree: $("fm-tree"), side: $("fm-side-tree"), list: $("fm-list"),
    empty: $("fm-empty"), drop: $("fm-drop"), status: $("fm-status"), upload: $("fm-upload-input"),
    trashToggle: $("fm-trash-toggle"), trashBar: $("fm-trash-bar"), selbar: $("fm-selbar"),
    selcount: $("fm-selcount"), dlg: $("fm-dialog"), dlgTitle: $("fm-dialog-title"),
    dlgBody: $("fm-dialog-body"), dlgFoot: $("fm-dialog-foot"), listWrap: $("fm-list-wrap"),
  };
  const state = { folders: [], files: [], trash: [], cwd: "", trashView: false, sel: new Set(), open: new Set([""]) };
  const NL = () => window.NL || {};

  function status(msg, isErr) {
    els.status.textContent = msg || "";
    els.status.classList.toggle("fm-status--err", !!isErr);
    if (msg) setTimeout(() => { if (els.status.textContent === msg) els.status.textContent = ""; }, 5000);
  }
  function fmtSize(n) {
    if (n == null) return "";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
    return (n / 1073741824).toFixed(2) + " GB";
  }
  function fmtDate(s) {
    if (!s) return "";
    const d = new Date(s);
    return isNaN(d) ? "" : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }
  const leaf = (f) => (f ? f.split("/").pop() : "Files");
  const parentOf = (f) => (f.includes("/") ? f.slice(0, f.lastIndexOf("/")) : "");
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

  async function api(url, opts = {}, stepUp = false) {
    const o = Object.assign({ credentials: "include" }, opts);
    if (o.json !== undefined) {
      o.method = o.method || "POST";
      o.headers = { "Content-Type": "application/json" };
      o.body = JSON.stringify(o.json);
      delete o.json;
    }
    const r = stepUp && NL().stepUpFetch ? await NL().stepUpFetch(url, o) : await fetch(url, o);
    if (r.status === 401 && NL().showAuth) NL().showAuth();
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.message || d.error || `HTTP ${r.status}`);
    return d;
  }

  async function refresh() {
    try {
      const [t, tr] = await Promise.all([api("/api/fm/tree"), state.trashView ? api("/api/fm/trash") : Promise.resolve(null)]);
      state.folders = t.folders || [];
      state.files = t.files || [];
      state.trashCount = t.trash_count || 0;
      if (tr) state.trash = tr.files || [];
      if (state.cwd && !state.folders.includes(state.cwd)) state.cwd = "";
      render();
    } catch (e) { status(e.message, true); }
  }

  function go(folder) {
    state.cwd = folder;
    state.trashView = false;
    state.sel.clear();
    let p = folder;
    while (p) { state.open.add(p); p = parentOf(p); }
    if (NL().setMode && panel.classList.contains("hidden")) NL().setMode("files");
    showManager();
    render();
  }

  function render() {
    renderCrumbs();
    renderTree(els.tree);
    renderTree(els.side);
    renderList();
    els.trashToggle.setAttribute("aria-pressed", String(state.trashView));
    els.trashToggle.textContent = state.trashCount ? `Trash (${state.trashCount})` : "Trash";
    els.trashBar.hidden = !state.trashView;
    renderSelbar();
  }

  function renderCrumbs() {
    els.crumbs.innerHTML = "";
    if (state.trashView) { els.crumbs.appendChild(el("span", "fm-crumb fm-crumb--cur", "Trash")); return; }
    const parts = state.cwd ? state.cwd.split("/") : [];
    const items = [["", "Files"]].concat(parts.map((p, i) => [parts.slice(0, i + 1).join("/"), p]));
    items.forEach(([path, label], i) => {
      if (i) els.crumbs.appendChild(el("span", "fm-crumb-sep", "/"));
      const b = el("button", "fm-crumb" + (i === items.length - 1 ? " fm-crumb--cur" : ""), label);
      b.type = "button";
      b.addEventListener("click", () => go(path));
      dropTarget(b, path);
      els.crumbs.appendChild(b);
    });
    if (window.NLFav) els.crumbs.appendChild(window.NLFav.star("files", state.cwd));
  }

  function children(folder) {
    return state.folders.filter((f) => parentOf(f) === folder && f !== folder).sort((a, b) => a.localeCompare(b));
  }

  function renderTree(host) {
    if (!host) return;
    host.innerHTML = "";
    const ul = el("ul", "fm-tree__list");
    const add = (folder, depth, parentUl) => {
      const li = el("li", "fm-tree__item");
      const row = el("div", "fm-tree__row" + (!state.trashView && state.cwd === folder ? " is-active" : ""));
      row.style.setProperty("--fm-depth", depth);
      const kids = children(folder);
      const tw = el("button", "fm-tree__twisty", kids.length ? (state.open.has(folder) ? "▾" : "▸") : "");
      tw.type = "button";
      tw.tabIndex = -1;
      tw.setAttribute("aria-hidden", "true");
      tw.addEventListener("click", (e) => { e.stopPropagation(); state.open.has(folder) ? state.open.delete(folder) : state.open.add(folder); render(); });
      const name = el("button", "fm-tree__name", (folder ? "📁 " : "🗂 ") + leaf(folder));
      name.type = "button";
      name.addEventListener("click", () => go(folder));
      dropTarget(row, folder);
      row.append(tw, name);
      if (window.NLFav) row.appendChild(window.NLFav.star("files", folder));
      li.appendChild(row);
      if (kids.length && state.open.has(folder)) {
        const sub = el("ul", "fm-tree__list");
        kids.forEach((k) => add(k, depth + 1, sub));
        li.appendChild(sub);
      }
      parentUl.appendChild(li);
    };
    add("", 0, ul);
    const t = el("li", "fm-tree__item");
    const tr = el("div", "fm-tree__row" + (state.trashView ? " is-active" : ""));
    const tb = el("button", "fm-tree__name", "🗑 Trash" + (state.trashCount ? ` (${state.trashCount})` : ""));
    tb.type = "button";
    tb.addEventListener("click", () => setTrash(true));
    tr.append(el("span", "fm-tree__twisty"), tb);
    t.appendChild(tr);
    ul.appendChild(t);
    host.appendChild(ul);
  }

  function rowsForView() {
    if (state.trashView) return { folders: [], files: state.trash.slice().sort((a, b) => (b.trashed_at || "").localeCompare(a.trashed_at || "")) };
    return {
      folders: children(state.cwd),
      files: state.files.filter((f) => (f.folder || "") === state.cwd).sort((a, b) => String(a.name).localeCompare(String(b.name))),
    };
  }

  function icon(f) {
    if (f.preview === "image") return "🖼";
    if (f.preview === "text") return "📄";
    return "📦";
  }

  function renderList() {
    const { folders, files } = rowsForView();
    els.list.innerHTML = "";
    els.empty.hidden = folders.length + files.length > 0;
    els.empty.textContent = state.trashView ? "Trash is empty." : "This folder is empty. Drop files here or use Upload.";
    folders.forEach((f) => {
      const li = row("folder:" + f, "📁", leaf(f), "Folder", "");
      li.classList.add("fm-row--folder");
      li.querySelector(".fm-row__name").addEventListener("click", () => go(f));
      li.draggable = true;
      li.addEventListener("dragstart", (e) => dragItems(e, "folder:" + f));
      dropTarget(li, f);
      menu(li, [
        ["Open", () => go(f)],
        ["Rename", () => renameFolder(f)],
        ["Move", () => moveDialog([], [f])],
        ["Delete", () => trashItems([], [f]), "danger"],
      ]);
      els.list.appendChild(li);
    });
    files.forEach((f) => {
      const meta = state.trashView ? `${f.folder ? f.folder + " · " : ""}deleted ${fmtDate(f.trashed_at)}` : fmtDate(f.updated_at);
      const li = row("file:" + f.id, icon(f), f.name, fmtSize(f.size), meta);
      li.querySelector(".fm-row__name").addEventListener("click", () => (state.trashView ? null : openItem(f)));
      if (!state.trashView) {
        li.draggable = true;
        li.addEventListener("dragstart", (e) => dragItems(e, "file:" + f.id));
        menu(li, [
          ["Open", () => openItem(f)],
          f.preview !== "none" ? ["Preview", () => preview(f)] : null,
          ["Download", () => download(f)],
          ["Rename", () => renameFile(f)],
          ["Move", () => moveDialog([f.id], [])],
          ["Delete", () => trashItems([f.id], []), "danger"],
        ]);
      } else {
        menu(li, [
          ["Restore", () => restore([f.id])],
          ["Delete forever", () => purge([f.id]), "danger"],
        ]);
      }
      els.list.appendChild(li);
    });
  }

  function row(key, ic, name, size, meta) {
    const li = el("li", "fm-row");
    li.dataset.key = key;
    if (state.sel.has(key)) li.classList.add("is-selected");
    const cb = el("input", "fm-row__check");
    cb.type = "checkbox";
    cb.checked = state.sel.has(key);
    cb.setAttribute("aria-label", "Select " + name);
    cb.addEventListener("change", () => { cb.checked ? state.sel.add(key) : state.sel.delete(key); li.classList.toggle("is-selected", cb.checked); renderSelbar(); });
    const nm = el("button", "fm-row__name");
    nm.type = "button";
    nm.append(el("span", "fm-row__icon", ic), el("span", "fm-row__label", name));
    const sz = el("span", "fm-row__size", size);
    const mt = el("span", "fm-row__meta", meta);
    li.append(cb, nm, sz, mt);
    return li;
  }

  function menu(li, items) {
    const b = el("button", "ghost tiny fm-row__more", "⋯");
    b.type = "button";
    b.setAttribute("aria-label", "Actions");
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      closeMenus();
      const m = el("div", "fm-menu");
      m.setAttribute("role", "menu");
      items.filter(Boolean).forEach(([label, fn, kind]) => {
        const it = el("button", "fm-menu__item" + (kind === "danger" ? " fm-danger" : ""), label);
        it.type = "button";
        it.setAttribute("role", "menuitem");
        it.addEventListener("click", () => { closeMenus(); fn(); });
        m.appendChild(it);
      });
      root.appendChild(m);
      const r = b.getBoundingClientRect();
      m.style.right = Math.max(8, window.innerWidth - r.right) + "px";
      const h = m.offsetHeight;
      m.style.top = (r.bottom + h + 8 > window.innerHeight ? Math.max(8, r.top - h) : r.bottom) + "px";
    });
    li.appendChild(b);
  }
  function closeMenus() { root.querySelectorAll(".fm-menu").forEach((m) => m.remove()); }
  document.addEventListener("click", (e) => { if (!e.target.closest || !e.target.closest(".fm-menu")) closeMenus(); });

  function selected() {
    const ids = [], folders = [];
    state.sel.forEach((k) => { if (k.startsWith("file:")) ids.push(k.slice(5)); else folders.push(k.slice(7)); });
    return { ids, folders };
  }
  function renderSelbar() {
    const n = state.sel.size;
    els.selbar.hidden = n === 0;
    els.selcount.textContent = `${n} selected`;
    els.selbar.querySelectorAll("[data-bulk]").forEach((b) => {
      const k = b.dataset.bulk;
      b.hidden = state.trashView ? (k === "move" || k === "trash" || k === "zip") : (k === "restore" || k === "purge");
    });
  }
  els.selbar.addEventListener("click", (e) => {
    const k = e.target.dataset && e.target.dataset.bulk;
    if (!k) return;
    const { ids, folders } = selected();
    if (k === "clear") { state.sel.clear(); return render(); }
    if (k === "move") return moveDialog(ids, folders);
    if (k === "zip") return downloadZip(ids, folders);
    if (k === "trash") return trashItems(ids, folders);
    if (k === "restore") return restore(ids);
    if (k === "purge") return purge(ids);
  });

  // ---- actions ----
  function showManager() { panel.classList.remove("fm-editing"); }
  function openItem(f) {
    if (f.preview === "image") return preview(f);
    if (f.preview === "text" && NL().openFile) { NL().openFile(f); return; }
    download(f);
  }
  function download(f) {
    const a = document.createElement("a");
    a.href = `/api/fm/files/${encodeURIComponent(f.id)}/download`;
    a.download = f.name || "";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function dialog(title, body, buttons) {
    els.dlgTitle.textContent = title;
    els.dlgBody.innerHTML = "";
    if (body) els.dlgBody.appendChild(body);
    els.dlgFoot.innerHTML = "";
    return new Promise((resolve) => {
      buttons.forEach(([label, value, cls]) => {
        const b = el("button", cls || "ghost toolbar-btn", label);
        b.type = "submit";
        b.value = value;
        els.dlgFoot.appendChild(b);
      });
      els.dlg.addEventListener("close", () => resolve(els.dlg.returnValue), { once: true });
      els.dlg.returnValue = "";
      if (els.dlg.showModal) els.dlg.showModal(); else els.dlg.setAttribute("open", "");
      const inp = els.dlgBody.querySelector("input,select");
      if (inp) setTimeout(() => inp.focus(), 0);
    });
  }
  async function ask(title, value) {
    const inp = el("input", "fm-input");
    inp.value = value || "";
    inp.maxLength = 200;
    inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); els.dlg.close("ok"); } });
    const v = await dialog(title, inp, [["Cancel", "cancel"], ["OK", "ok", "accent-btn toolbar-btn"]]);
    return v === "ok" ? inp.value.trim() : null;
  }

  async function preview(f) {
    const box = el("div", "fm-preview");
    if (f.preview === "image") {
      const img = el("img", "fm-preview__img");
      img.alt = f.name;
      img.src = `/api/fm/files/${encodeURIComponent(f.id)}/preview`;
      box.appendChild(img);
    } else {
      const pre = el("pre", "fm-preview__text", "Loading…");
      box.appendChild(pre);
      api(`/api/fm/files/${encodeURIComponent(f.id)}/content`).then((d) => {
        const t = d.content || "";
        pre.textContent = t.length > 200000 ? t.slice(0, 200000) + "\n…(truncated)" : t;
      }).catch((e) => { pre.textContent = e.message; });
    }
    const btns = [["Download", "dl"]];
    if (f.preview === "text") btns.push(["Edit", "edit"]);
    btns.push(["Close", "cancel", "accent-btn toolbar-btn"]);
    const v = await dialog(f.name, box, btns);
    if (v === "dl") download(f);
    if (v === "edit" && NL().openFile) NL().openFile(f);
  }

  async function newFolder() {
    const name = await ask(state.cwd ? `New folder in ${state.cwd}` : "New folder");
    if (!name) return;
    try { await api("/api/fm/folders", { json: { parent: state.cwd, name } }); status(`Created ${name}`); refresh(); }
    catch (e) { status(e.message, true); }
  }
  async function renameFile(f) {
    const name = await ask("Rename file", f.name);
    if (!name || name === f.name) return;
    try { await api("/api/fm/rename", { json: { id: f.id, name } }); status("Renamed"); refresh(); NL().loadFiles && NL().loadFiles(); }
    catch (e) { status(e.message, true); }
  }
  async function renameFolder(f) {
    const name = await ask("Rename folder", leaf(f));
    if (!name || name === leaf(f)) return;
    try { await api("/api/fm/rename", { json: { folder: f, name } }); status("Renamed"); refresh(); }
    catch (e) { status(e.message, true); }
  }
  async function moveDialog(ids, folders) {
    if (!ids.length && !folders.length) return;
    const sel = el("select", "fm-input");
    [""].concat(state.folders.slice().sort()).forEach((f) => {
      if (folders.some((src) => f === src || f.startsWith(src + "/"))) return;
      const o = el("option", null, f ? "/ " + f.split("/").join(" / ") : "/ (Files root)");
      o.value = f;
      if (f === state.cwd) o.selected = true;
      sel.appendChild(o);
    });
    const v = await dialog(`Move ${ids.length + folders.length} item(s) to…`, sel, [["Cancel", "cancel"], ["Move", "ok", "accent-btn toolbar-btn"]]);
    if (v !== "ok") return;
    doMove(ids, folders, sel.value);
  }
  async function doMove(ids, folders, dest) {
    try { const d = await api("/api/fm/move", { json: { ids, folders, dest } }); state.sel.clear(); status(`Moved ${d.moved}`); refresh(); }
    catch (e) { status(e.message, true); }
  }
  async function trashItems(ids, folders) {
    if (!ids.length && !folders.length) return;
    try { const d = await api("/api/fm/trash", { json: { ids, folders } }, true); state.sel.clear(); status(`Moved ${d.trashed} file(s) to Trash`); refresh(); NL().loadFiles && NL().loadFiles(); }
    catch (e) { status(e.message, true); }
  }
  async function restore(ids) {
    if (!ids.length) return;
    try { const d = await api("/api/fm/restore", { json: { ids } }); state.sel.clear(); status(`Restored ${d.restored}`); refresh(); NL().loadFiles && NL().loadFiles(); }
    catch (e) { status(e.message, true); }
  }
  async function purge(ids) {
    if (!ids.length) return;
    const v = await dialog("Delete forever?", el("p", null, `${ids.length} item(s) will be removed permanently.`), [["Cancel", "cancel"], ["Delete forever", "ok", "accent-btn toolbar-btn fm-danger"]]);
    if (v !== "ok") return;
    try { await api("/api/fm/purge", { json: { ids } }, true); state.sel.clear(); status("Deleted"); refresh(); }
    catch (e) { status(e.message, true); }
  }
  async function emptyTrash() {
    const v = await dialog("Empty trash?", el("p", null, "Everything in Trash will be removed permanently."), [["Cancel", "cancel"], ["Empty trash", "ok", "accent-btn toolbar-btn fm-danger"]]);
    if (v !== "ok") return;
    try { const d = await api("/api/fm/empty-trash", { json: {} }, true); status(`Removed ${d.purged} item(s)`); refresh(); }
    catch (e) { status(e.message, true); }
  }
  function setTrash(on) {
    state.trashView = on;
    state.sel.clear();
    showManager();
    refresh();
  }

  // Chunked, resumable uploads (up to ~5 GB per file). The upload id is remembered in
  // localStorage per file+folder, so re-picking the same file after a drop resumes it.
  const UP_KEY = "nl.fm.uploads";
  const upStore = () => { try { return JSON.parse(localStorage.getItem(UP_KEY) || "{}"); } catch (_) { return {}; } };
  const upSave = (o) => { try { localStorage.setItem(UP_KEY, JSON.stringify(o)); } catch (_) {} };
  const upFp = (f, folder) => [folder, f.name, f.size, f.lastModified].join("|");
  async function uploadOne(f, folder, idx, total) {
    const fp = upFp(f, folder);
    const store = upStore();
    let up = null;
    if (store[fp]) { try { up = await api(`/api/fm/uploads/${store[fp]}`); } catch (_) { up = null; } }
    if (!up) {
      up = await api("/api/fm/uploads", { json: { name: f.name, size: f.size, folder } });
      const s2 = upStore(); s2[fp] = up.upload_id; upSave(s2);
    }
    const id = up.upload_id, cs = up.chunk_size || 8388608;
    let off = up.received || 0, tries = 0;
    while (off < f.size) {
      const end = Math.min(off + cs, f.size);
      const pct = f.size ? Math.floor((off / f.size) * 100) : 100;
      status(`Uploading ${idx}/${total}: ${f.name} — ${pct}% (${fmtSize(off)} of ${fmtSize(f.size)})`);
      try {
        const r = await fetch(`/api/fm/uploads/${id}/chunk?offset=${off}`, {
          method: "POST", credentials: "include", headers: { "Content-Type": "application/octet-stream" },
          body: f.slice(off, end),
        });
        const d = await r.json().catch(() => ({}));
        if (r.status === 409 && typeof d.received === "number") { off = d.received; continue; }
        if (!r.ok) throw new Error(d.message || d.error || `HTTP ${r.status}`);
        off = d.received; tries = 0;
      } catch (e) {
        if (++tries > 5) throw e;
        await new Promise((res) => setTimeout(res, 1000 * tries));
        try { off = (await api(`/api/fm/uploads/${id}`)).received; } catch (_) {}
      }
    }
    const done = await api(`/api/fm/uploads/${id}/complete`, { json: {} });
    const s3 = upStore(); delete s3[fp]; upSave(s3);
    return done;
  }
  async function uploadFiles(list) {
    list = Array.from(list || []);
    if (!list.length) return;
    const folder = state.cwd;
    let ok = 0; const errs = [];
    for (let i = 0; i < list.length; i++) {
      try { await uploadOne(list[i], folder, i + 1, list.length); ok++; }
      catch (e) { errs.push(`${list[i].name}: ${e.message}`); }
    }
    status(`Uploaded ${ok} file(s)` + (errs.length ? ` — ${errs.length} failed: ${errs[0]}` : ""), errs.length > 0);
    refresh();
    NL().loadFiles && NL().loadFiles();
  }
  function downloadZip(ids, folders) {
    const q = new URLSearchParams();
    if (ids.length) q.set("ids", ids.join(","));
    if (folders.length) q.set("folders", folders.join(","));
    const a = document.createElement("a");
    a.href = `/api/fm/zip?${q}`;
    a.rel = "noopener";
    document.body.appendChild(a); a.click(); a.remove();
    status("Preparing zip download…");
  }

  // ---- drag & drop ----
  function dragItems(e, key) {
    const keys = state.sel.has(key) ? [...state.sel] : [key];
    e.dataTransfer.setData("application/x-nl-fm", JSON.stringify(keys));
    e.dataTransfer.effectAllowed = "move";
  }
  function dropTarget(node, folder) {
    node.addEventListener("dragover", (e) => {
      if (!e.dataTransfer.types.includes("application/x-nl-fm")) return;
      e.preventDefault();
      e.stopPropagation();
      node.classList.add("is-drop");
    });
    node.addEventListener("dragleave", () => node.classList.remove("is-drop"));
    node.addEventListener("drop", (e) => {
      const raw = e.dataTransfer.getData("application/x-nl-fm");
      node.classList.remove("is-drop");
      if (!raw) return;
      e.preventDefault();
      e.stopPropagation();
      const keys = JSON.parse(raw);
      const ids = keys.filter((k) => k.startsWith("file:")).map((k) => k.slice(5));
      const folders = keys.filter((k) => k.startsWith("folder:")).map((k) => k.slice(7)).filter((f) => f !== folder);
      if (ids.length || folders.length) doMove(ids, folders, folder);
    });
  }
  let dragDepth = 0;
  const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files");
  root.addEventListener("dragenter", (e) => { if (!hasFiles(e) || state.trashView) return; dragDepth++; els.drop.hidden = false; });
  root.addEventListener("dragleave", (e) => { if (!hasFiles(e)) return; if (--dragDepth <= 0) { dragDepth = 0; els.drop.hidden = true; } });
  root.addEventListener("dragover", (e) => { if (hasFiles(e) && !state.trashView) e.preventDefault(); });
  root.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth = 0;
    els.drop.hidden = true;
    if (!state.trashView) uploadFiles(e.dataTransfer.files);
  });

  // ---- wiring ----
  els.upload.addEventListener("change", () => { const l = els.upload.files; uploadFiles(l); els.upload.value = ""; });
  $("fm-new-folder").addEventListener("click", newFolder);
  $("fm-new-file").addEventListener("click", () => { const b = $("btn-new-file"); if (b) b.click(); });
  els.trashToggle.addEventListener("click", () => setTrash(!state.trashView));
  $("fm-empty-trash").addEventListener("click", emptyTrash);
  const back = $("fm-back");
  if (back) back.addEventListener("click", () => { showManager(); refresh(); });
  document.addEventListener("nl:editor-open", () => panel.classList.add("fm-editing"));
  document.addEventListener("nl:files-loaded", refresh);

  window.NLFiles = { refresh, go, state };
  window.NLFiles = { go, rerender: () => render(), cwd: () => state.cwd };
})();
