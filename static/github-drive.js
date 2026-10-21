/* Nullink GitHub drive (gh1): repos -> branches -> tree -> file viewer (CodeMirror 6, the
   vendored advanced-editor bundle). Read-only by default; Edit needs a fresh authenticator code
   (NL.stepUpFetch), Commit needs a message and offers commit-to-branch or new branch + PR.
   The GitHub token never reaches the browser: everything goes through /api/gh/*. */
import * as CM from "/vendor/codemirror/codemirror.bundle.js";

const $ = (id) => document.getElementById(id);
const root = $("gh");
const NL = () => window.NL || {};
const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
const enc = encodeURIComponent;
const state = { repo: null, ref: null, path: "", file: null, editing: false, wrap: false, inited: false, branches: [] };
const els = { crumbs: $("gh-crumbs"), list: $("gh-list"), viewer: $("gh-viewer"), cm: $("gh-cm"), name: $("gh-file-name"),
  edit: $("gh-edit"), save: $("gh-save"), cancel: $("gh-cancel"), find: $("gh-find"), wrapB: $("gh-wrap"),
  status: $("gh-status"), branch: $("gh-branch"), mode: $("gh-mode"), unconf: $("gh-unconfigured"), banner: $("gh-banner"),
  dlg: $("fm-dialog"), dlgTitle: $("fm-dialog-title"), dlgBody: $("fm-dialog-body"), dlgFoot: $("fm-dialog-foot") };

function status(m, err) { els.status.textContent = m || ""; els.status.classList.toggle("fm-status--err", !!err); }
async function api(url, opts = {}, stepUp = false) {
  const o = Object.assign({ credentials: "include" }, opts);
  if (o.json !== undefined) { o.method = "POST"; o.headers = { "Content-Type": "application/json" }; o.body = JSON.stringify(o.json); delete o.json; }
  const r = stepUp && NL().stepUpFetch ? await NL().stepUpFetch(url, o) : await fetch(url, o);
  if (r.status === 401 && NL().showAuth) NL().showAuth();
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(d.message || d.error || `HTTP ${r.status}`); e.code = d.error; e.status = r.status; e.data = d; throw e; }
  return d;
}

// ---- editor (CodeMirror, read-only until Edit) ----
const LANG = { md: () => CM.markdown(), markdown: () => CM.markdown(), json: () => CM.json(), css: () => CM.css(),
  js: () => CM.javascript(), mjs: () => CM.javascript(), jsx: () => CM.javascript(), ts: () => CM.javascript({ typescript: true }),
  tsx: () => CM.javascript({ typescript: true }), py: () => CM.python(), html: () => CM.html(), htm: () => CM.html(),
  yml: () => CM.yaml(), yaml: () => CM.yaml(), xml: () => CM.xml(), svg: () => CM.xml(),
  sh: () => CM.StreamLanguage.define(CM.shell), bash: () => CM.StreamLanguage.define(CM.shell) };
const ro = new CM.Compartment(), lang = new CM.Compartment(), wrapC = new CM.Compartment();
let view = null;
function ensureView() {
  if (view) return view;
  view = new CM.EditorView({ parent: els.cm, state: CM.EditorState.create({ doc: "", extensions: [
    CM.basicSetup, CM.oneDark, ro.of([CM.EditorState.readOnly.of(true), CM.EditorView.editable.of(false)]), lang.of([]), wrapC.of([]),
  ] }) });
  return view;
}
function setDoc(text, name) {
  const v = ensureView();
  const ext = String(name || "").toLowerCase().split(".").pop();
  v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: text }, effects: lang.reconfigure(LANG[ext] ? LANG[ext]() : []) });
}
function setEditable(on) {
  state.editing = on;
  ensureView().dispatch({ effects: ro.reconfigure([CM.EditorState.readOnly.of(!on), CM.EditorView.editable.of(on)]) });
  els.edit.hidden = on; els.save.hidden = !on; els.cancel.hidden = !on;
  els.mode.textContent = on ? "Editing" : "Read-only";
  els.mode.classList.toggle("gh-editing", on);
  els.banner.textContent = on ? "Editing. Commit needs a message; the file's sha is re-checked on GitHub before committing."
    : "Read-only. Editing needs a fresh authenticator code; every commit is logged.";
}
const dirty = () => state.editing && state.file && view && view.state.doc.toString() !== state.file.content;
window.addEventListener("beforeunload", (e) => { if (dirty()) { e.preventDefault(); e.returnValue = ""; } });
function guard() { return !dirty() || confirm("Discard unsaved changes?"); }

// ---- navigation ----
function crumbs() {
  els.crumbs.textContent = "";
  const add = (label, fn, cur) => { const b = el("button", "fm-crumb" + (cur ? " fm-crumb--cur" : ""), label); b.type = "button"; b.onclick = () => guard() && fn(); els.crumbs.appendChild(b); };
  const sep = () => els.crumbs.appendChild(el("span", "fm-crumb-sep", "/"));
  add("GitHub", () => repos(), !state.repo);
  if (!state.repo) return;
  sep(); add(state.repo, () => tree(""), !state.path && !state.file);
  const parts = state.path ? state.path.split("/") : [];
  let acc = "";
  parts.forEach((p, i) => { acc += (acc ? "/" : "") + p; const target = acc; sep(); add(p, () => tree(target), i === parts.length - 1 && !state.file); });
  if (state.file) { sep(); els.crumbs.appendChild(el("span", "fm-crumb fm-crumb--cur", state.file.name)); }
  if (!state.file && window.NLFav) els.crumbs.appendChild(window.NLFav.star("github", `${state.repo}@${state.ref}:${state.path}`));
}
function showList() { els.viewer.hidden = true; els.list.hidden = false; }
async function init() {
  if (state.inited) return;
  state.inited = true;
  try {
    const s = await api("/api/gh/status");
    if (!s.configured) { els.unconf.hidden = false; els.banner.hidden = true; els.list.hidden = true; crumbs(); return; }
    status(`Signed in to GitHub as ${s.login}`);
    if (!state.repo) repos();
  } catch (e) { state.inited = false; status(e.message, true); }
}
async function repos() {
  state.repo = null; state.file = null; state.path = ""; els.branch.hidden = true; setEditable(false); showList(); crumbs();
  try {
    const d = await api("/api/gh/repos");
    els.list.textContent = "";
    d.repos.forEach((r) => {
      const li = el("li", "fm-row gh-row");
      const b = el("button", "fm-row__name", "📦 " + r.full_name); b.type = "button";
      b.onclick = () => openRepo(r.full_name, r.default_branch);
      li.append(b, el("span", "fm-row__meta", (r.private ? "Private · " : "Public · ") + (r.default_branch || "")));
      els.list.appendChild(li);
    });
  } catch (e) { status(e.message, true); }
}
async function openRepo(repo, ref, path = "") {
  state.repo = repo; state.ref = ref;
  try {
    const d = await api(`/api/gh/branches?repo=${enc(repo)}`);
    state.branches = d.branches;
    els.branch.textContent = "";
    d.branches.forEach((b) => { const o = el("option", null, b.name + (b.protected ? " 🔒" : "")); o.value = b.name; if (b.name === ref) o.selected = true; els.branch.appendChild(o); });
    els.branch.hidden = false;
  } catch (e) { status(e.message, true); }
  tree(path);
}
els.branch.addEventListener("change", () => { if (!guard()) { els.branch.value = state.ref; return; } state.ref = els.branch.value; tree(state.path); });
async function tree(path) {
  state.path = path; state.file = null; setEditable(false); showList(); crumbs();
  try {
    const d = await api(`/api/gh/tree?repo=${enc(state.repo)}&ref=${enc(state.ref)}&path=${enc(path)}`);
    els.list.textContent = "";
    if (path) { const li = el("li", "fm-row gh-row"); const b = el("button", "fm-row__name", "⬑ .."); b.type = "button"; b.onclick = () => tree(path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : ""); li.appendChild(b); els.list.appendChild(li); }
    d.items.forEach((it) => {
      const li = el("li", "fm-row gh-row");
      const b = el("button", "fm-row__name", (it.type === "dir" ? "📁 " : "📄 ") + it.name); b.type = "button";
      b.onclick = () => (it.type === "dir" ? tree(it.path) : openFile(it.path));
      li.append(b, el("span", "fm-row__meta", it.type === "dir" ? "Folder" : (it.size < 1024 ? it.size + " B" : (it.size / 1024).toFixed(1) + " KB")));
      els.list.appendChild(li);
    });
    status("");
  } catch (e) { status(e.message, true); }
}
async function openFile(path) {
  try {
    const d = await api(`/api/gh/file?repo=${enc(state.repo)}&ref=${enc(state.ref)}&path=${enc(path)}`);
    state.file = d;
    els.list.hidden = true; els.viewer.hidden = false; els.name.textContent = d.name;
    setEditable(false);
    if (d.binary || d.too_large || d.content == null) { setDoc(d.too_large ? "(File larger than 1 MB — open it on GitHub.)" : "(Binary file — not shown.)", ""); els.edit.hidden = true; }
    else setDoc(d.content, d.name);
    crumbs();
  } catch (e) { status(e.message, true); }
}
els.edit.addEventListener("click", async () => {
  try { await api("/api/gh/edit", { json: { repo: state.repo, path: state.file.path } }, true); setEditable(true); status("Editing — commit when ready."); }
  catch (e) { status(e.code === "step_up_required" ? "Authenticator code needed to edit." : e.message, true); }
});
els.cancel.addEventListener("click", () => { if (!guard()) return; setDoc(state.file.content, state.file.name); setEditable(false); });
els.find.addEventListener("click", () => view && CM.openSearchPanel(view));
els.wrapB.addEventListener("click", () => { state.wrap = !state.wrap; ensureView().dispatch({ effects: wrapC.reconfigure(state.wrap ? CM.EditorView.lineWrapping : []) }); });

function commitDialog() {
  els.dlgTitle.textContent = `Commit ${state.file.name}`;
  els.dlgBody.textContent = "";
  const msg = el("input"); msg.placeholder = "Commit message (required)"; msg.className = "gh-msg"; msg.maxLength = 500;
  const modeSel = el("select");
  [["branch", `Commit to ${state.ref}`], ["pr", "New branch + pull request"]].forEach(([v, t]) => { const o = el("option", null, t); o.value = v; modeSel.appendChild(o); });
  const nb = el("input"); nb.placeholder = "new-branch-name"; nb.value = `nullink/edit-${Date.now().toString(36)}`; nb.hidden = true;
  modeSel.onchange = () => { nb.hidden = modeSel.value !== "pr"; };
  els.dlgBody.append(el("p", "hint", `${state.repo} · ${state.file.path}`), msg, modeSel, nb);
  els.dlgFoot.textContent = "";
  const go = el("button", "accent-btn toolbar-btn", "Commit"); go.type = "button";
  const cancel = el("button", "ghost toolbar-btn", "Cancel"); cancel.type = "submit"; cancel.value = "cancel";
  els.dlgFoot.append(cancel, go);
  go.onclick = async () => {
    if (!msg.value.trim()) { msg.focus(); status("A commit message is required.", true); return; }
    try {
      const d = await api("/api/gh/commit", { json: { repo: state.repo, branch: state.ref, path: state.file.path, sha: state.file.sha,
        content: view.state.doc.toString(), message: msg.value.trim(), mode: modeSel.value, new_branch: nb.value.trim(), pr_title: msg.value.trim() } }, true);
      els.dlg.close();
      state.file.content = view.state.doc.toString(); state.file.sha = d.sha; setEditable(false);
      status(d.pr_url ? `Committed to ${d.branch}; PR #${d.pr_number} opened.` : `Committed ${String(d.commit || "").slice(0, 7)} to ${d.branch}.`);
    } catch (e) {
      status(e.code === "changed_since_open" ? "The file changed on GitHub since you opened it. Copy your edits, reload, and re-apply." : e.message, true);
    }
  };
  els.dlg.returnValue = "";
  els.dlg.showModal ? els.dlg.showModal() : els.dlg.setAttribute("open", "");
  setTimeout(() => msg.focus(), 0);
}
els.save.addEventListener("click", commitDialog);

document.addEventListener("nl:drive", (e) => { if (e.detail === "github") init(); });
function openFav(p) {
  const m = /^([^@]+)@([^:]+):(.*)$/.exec(p || "");
  if (!m) return;
  window.NLServerDrive && window.NLServerDrive.pick("github");
  openRepo(m[1], m[2], m[3]);
}
window.NLGitHub = { open: openFav, repos, tree: (p) => tree(p), file: (p) => openFile(p), openRepo, state };
