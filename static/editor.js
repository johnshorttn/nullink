/* Nullink advanced editor (ed1). CodeMirror 6 (vendored ESM bundle, no build step) layered over
   app.js's #editor textarea: the textarea's `value` is proxied to the active document so Save,
   Ask Morc, Preview, Pull/Accept and Diff keep working unchanged.
   Modes: HTML code, Rich text (WYSIWYG on the same HTML), Markdown (+ live preview), plain text,
   JSON, CSS, JavaScript, Python, Shell, YAML, XML. Every HTML render is sanitized (NLSanitize)
   and previews run in a sandboxed iframe (no scripts, no same-origin). */
import * as CM from "/vendor/codemirror/codemirror.bundle.js";

const $ = (id) => document.getElementById(id);
const ta = $("editor"), wrap = $("editor-wrap"), gutter = $("gutter"), nameEl = $("editor-filename");
const S = window.NLSanitize;
if (ta && wrap && S) init();

function init() {
  const MODES = {
    html: { label: "HTML code", lang: () => CM.html(), layout: "code", tools: "html" },
    rich: { label: "Rich text (visual)", lang: () => CM.html(), layout: "wysiwyg", tools: "rich" },
    markdown: { label: "Markdown", lang: () => CM.markdown(), layout: "split", tools: "markdown" },
    text: { label: "Plain text", lang: () => [], layout: "code", tools: "" },
    json: { label: "JSON", lang: () => CM.json(), layout: "code", tools: "json" },
    css: { label: "CSS", lang: () => CM.css(), layout: "code", tools: "" },
    javascript: { label: "JavaScript", lang: () => CM.javascript(), layout: "code", tools: "" },
    typescript: { label: "TypeScript", lang: () => CM.javascript({ typescript: true }), layout: "code", tools: "" },
    python: { label: "Python", lang: () => CM.python(), layout: "code", tools: "" },
    shell: { label: "Shell", lang: () => CM.StreamLanguage.define(CM.shell), layout: "code", tools: "" },
    yaml: { label: "YAML", lang: () => CM.yaml(), layout: "code", tools: "" },
    xml: { label: "XML", lang: () => CM.xml(), layout: "code", tools: "" },
  };
  const EXT = { html: "html", htm: "html", xhtml: "html", md: "markdown", markdown: "markdown", mdx: "markdown",
    json: "json", jsonl: "text", css: "css", scss: "css", less: "css", js: "javascript", mjs: "javascript", cjs: "javascript",
    jsx: "javascript", ts: "typescript", tsx: "typescript", py: "python", pyw: "python", sh: "shell", bash: "shell",
    zsh: "shell", ksh: "shell", env: "shell", yml: "yaml", yaml: "yaml", xml: "xml", svg: "xml", plist: "xml" };
  const detect = (name) => {
    const n = String(name || "").toLowerCase();
    if (n === "dockerfile" || n === "makefile") return "shell";
    const ext = n.includes(".") ? n.split(".").pop() : "";
    return EXT[ext] || "text";
  };

  // ---- DOM ----
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const bar = el("div", "ed-bar"); bar.setAttribute("role", "toolbar"); bar.setAttribute("aria-label", "Editor");
  const sel = el("select", "ed-mode"); sel.setAttribute("aria-label", "Editor mode");
  for (const [id, m] of Object.entries(MODES)) { const o = el("option", "", m.label); o.value = id; sel.appendChild(o); }
  const btn = (label, title, fn, cls) => { const b = el("button", "ghost tiny ed-btn" + (cls ? " " + cls : ""), label); b.type = "button"; b.title = title; b.setAttribute("aria-label", title); b.addEventListener("mousedown", (e) => e.preventDefault()); b.addEventListener("click", fn); return b; };
  const common = el("span", "ed-group ed-common");
  const wrapBtn = btn("Wrap", "Toggle word wrap", () => setWrap(!state.wrap));
  common.append(
    btn("Find", "Find and replace (Ctrl/Cmd+F)", () => { if (state.layout === "wysiwyg") return; CM.openSearchPanel(view); }),
    wrapBtn,
    btn("Fold", "Fold all", () => CM.foldAll(view)),
    btn("Unfold", "Unfold all", () => CM.unfoldAll(view)),
  );
  const prevBtn = btn("Preview", "Toggle live preview", () => { state.preview = !state.preview; layout(); });
  common.appendChild(prevBtn);
  const tools = el("span", "ed-group ed-tools");
  const note = el("span", "ed-note muted-meta");
  bar.append(sel, common, tools, note);
  const body = el("div", "ed-body");
  const cmHost = el("div", "ed-cm");
  const wys = el("div", "ed-wys"); wys.contentEditable = "true"; wys.spellcheck = true; wys.setAttribute("role", "textbox"); wys.setAttribute("aria-multiline", "true"); wys.setAttribute("aria-label", "Rich text editor");
  const prev = el("iframe", "ed-prev"); prev.setAttribute("sandbox", ""); prev.setAttribute("referrerpolicy", "no-referrer"); prev.title = "Sanitized preview";
  body.append(cmHost, wys, prev);
  wrap.prepend(bar);
  wrap.appendChild(body);
  wrap.classList.add("ed-on");
  if (gutter) gutter.hidden = true;
  ta.hidden = true;

  // ---- CodeMirror ----
  const langC = new CM.Compartment(), wrapC = new CM.Compartment();
  const proto = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
  const state = { mode: "text", layout: "code", wrap: false, preview: false, silent: false, userPicked: false };
  const fire = () => ta.dispatchEvent(new Event("input", { bubbles: true }));
  let prevTimer = null;
  const view = new CM.EditorView({
    parent: cmHost,
    state: CM.EditorState.create({
      doc: proto.get.call(ta) || "",
      extensions: [
        CM.basicSetup, CM.oneDark, langC.of([]), wrapC.of([]),
        CM.keymap.of([{ key: "Mod-s", preventDefault: true, run: () => { save(); return true; } }]),
        CM.EditorView.updateListener.of((u) => {
          if (!u.docChanged || state.silent) return;
          fire();
          clearTimeout(prevTimer); prevTimer = setTimeout(renderPreview, 250);
        }),
      ],
    }),
  });
  const getDoc = () => view.state.doc.toString();
  function setDoc(v) {
    v = v == null ? "" : String(v);
    if (v === getDoc()) return;
    state.silent = true;
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v } });
    state.silent = false;
    if (state.layout === "wysiwyg") wys.innerHTML = S.sanitize(v);
    renderPreview();
  }
  // Proxy textarea.value <-> document so app.js (save, Ask Morc, diff, pull/accept) is unchanged.
  Object.defineProperty(ta, "value", {
    configurable: true,
    get() { return getDoc(); },
    set(v) { proto.set.call(ta, v); setDoc(v); },
  });
  function save() { const b = $("btn-save"); if (b && !b.disabled) b.click(); }

  // ---- WYSIWYG ----
  wys.addEventListener("input", () => {
    state.silent = true;
    const html = S.sanitize(wys.innerHTML);
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: html } });
    state.silent = false;
    fire();
  });
  wys.addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") { e.preventDefault(); save(); } });
  wys.addEventListener("paste", (e) => {
    const html = e.clipboardData && e.clipboardData.getData("text/html");
    if (!html) return;
    e.preventDefault();
    document.execCommand("insertHTML", false, S.sanitize(html));
  });
  const exec = (cmd, val) => { wys.focus(); document.execCommand(cmd, false, val); };
  function askUrl(label, isImg) {
    const raw = prompt(label, "https://");
    if (!raw) return null;
    const u = S.safeUrl(raw.trim(), isImg);
    if (!u) { alert("Only http(s), mailto or relative links are allowed."); return null; }
    return u;
  }
  function tableHtml(r = 3, c = 3) {
    const row = (tag) => "<tr>" + Array.from({ length: c }, () => `<${tag}>&nbsp;</${tag}>`).join("") + "</tr>";
    return "<table><thead>" + row("th") + "</thead><tbody>" + Array.from({ length: r - 1 }, () => row("td")).join("") + "</tbody></table><p></p>";
  }

  // ---- code helpers ----
  function wrapSel(before, after = before, placeholder = "text") {
    const r = view.state.selection.main;
    const t = view.state.sliceDoc(r.from, r.to) || placeholder;
    view.dispatch({ changes: { from: r.from, to: r.to, insert: before + t + after },
      selection: { anchor: r.from + before.length, head: r.from + before.length + t.length } });
    view.focus();
  }
  function linePrefix(prefix) {
    const r = view.state.selection.main;
    const changes = [];
    for (let pos = r.from; pos <= r.to;) {
      const line = view.state.doc.lineAt(pos);
      changes.push({ from: line.from, insert: prefix });
      pos = line.to + 1;
    }
    view.dispatch({ changes }); view.focus();
  }
  function insert(text) { const r = view.state.selection.main; view.dispatch({ changes: { from: r.from, to: r.to, insert: text } }); view.focus(); }
  function jsonDo(kind) {
    try {
      const v = JSON.parse(getDoc());
      if (kind === "check") { note.textContent = "✓ Valid JSON"; return; }
      insertAll(kind === "min" ? JSON.stringify(v) : JSON.stringify(v, null, 2) + "\n");
      note.textContent = "";
    } catch (e) { note.textContent = "✗ " + e.message; }
  }
  function insertAll(v) { view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v } }); }

  const TOOLBARS = {
    html: () => [
      btn("Visual", "Switch to rich text (visual) editing of this HTML", () => pick("rich", true), "ed-accent"),
      btn("<b>", "Bold tag", () => wrapSel("<strong>", "</strong>")),
      btn("<a>", "Link tag", () => wrapSel('<a href="https://">', "</a>", "link")),
      btn("<img>", "Image tag", () => insert('<img src="https://" alt="">')),
      btn("<table>", "Table", () => insert(tableHtml())),
    ],
    rich: () => [
      btn("</> Code", "Switch to HTML code", () => pick("html", true), "ed-accent"),
      btn("B", "Bold", () => exec("bold"), "ed-b"), btn("I", "Italic", () => exec("italic"), "ed-i"),
      btn("U", "Underline", () => exec("underline"), "ed-u"), btn("S", "Strikethrough", () => exec("strikeThrough"), "ed-s"),
      btn("H1", "Heading 1", () => exec("formatBlock", "<h1>")), btn("H2", "Heading 2", () => exec("formatBlock", "<h2>")),
      btn("¶", "Paragraph", () => exec("formatBlock", "<p>")), btn("❝", "Quote", () => exec("formatBlock", "<blockquote>")),
      btn("• List", "Bulleted list", () => exec("insertUnorderedList")), btn("1. List", "Numbered list", () => exec("insertOrderedList")),
      btn("Link", "Insert link", () => { const u = askUrl("Link URL", false); if (u) exec("createLink", u); }),
      btn("Image", "Insert image by URL", () => { const u = askUrl("Image URL", true); if (u) exec("insertImage", u); }),
      btn("Table", "Insert 3×3 table", () => exec("insertHTML", tableHtml())),
      btn("Clear", "Clear formatting", () => exec("removeFormat")),
      btn("↶", "Undo", () => exec("undo")), btn("↷", "Redo", () => exec("redo")),
    ],
    markdown: () => [
      btn("B", "Bold", () => wrapSel("**"), "ed-b"), btn("I", "Italic", () => wrapSel("_"), "ed-i"),
      btn("H", "Heading", () => linePrefix("## ")), btn("• List", "List", () => linePrefix("- ")),
      btn("Quote", "Quote", () => linePrefix("> ")), btn("`code`", "Code", () => wrapSel("`")),
      btn("Link", "Link", () => wrapSel("[", "](https://)", "link")), btn("Image", "Image", () => insert("![alt](https://)")),
      btn("Table", "Table", () => insert("\n| A | B |\n| --- | --- |\n|   |   |\n")),
    ],
    json: () => [btn("Format", "Pretty-print JSON", () => jsonDo("fmt")), btn("Minify", "Minify JSON", () => jsonDo("min")), btn("Validate", "Validate JSON", () => jsonDo("check"))],
  };

  // ---- layout / modes ----
  function setWrap(on) {
    state.wrap = on;
    view.dispatch({ effects: wrapC.reconfigure(on ? CM.EditorView.lineWrapping : []) });
    wrapBtn.setAttribute("aria-pressed", String(on)); wrapBtn.classList.toggle("is-on", on);
    wys.classList.toggle("ed-nowrap", !on);
  }
  function renderPreview() {
    if (prev.hidden) return;
    const doc = getDoc();
    let html;
    if (state.mode === "markdown") html = CM.marked.parse(doc, { async: false, gfm: true });
    else html = doc;
    prev.srcdoc = S.previewDoc(S.sanitize(html), true);
  }
  function layout() {
    const m = MODES[state.mode];
    let lay = m.layout;
    if (lay === "code" && state.preview && state.mode === "html") lay = "split";
    if (lay === "split" && state.mode === "markdown" && !state.preview) lay = "code";
    state.layout = lay;
    wrap.dataset.edLayout = lay;
    wrap.dataset.edMode = state.mode;
    cmHost.hidden = lay === "wysiwyg";
    wys.hidden = lay !== "wysiwyg";
    prev.hidden = lay !== "split";
    prevBtn.hidden = !(state.mode === "markdown" || state.mode === "html");
    prevBtn.setAttribute("aria-pressed", String(lay === "split")); prevBtn.classList.toggle("is-on", lay === "split");
    common.querySelectorAll(".ed-btn").forEach((b) => { if (b !== prevBtn) b.disabled = lay === "wysiwyg" && b !== wrapBtn; });
    tools.textContent = "";
    (TOOLBARS[m.tools] ? TOOLBARS[m.tools]() : []).forEach((b) => tools.appendChild(b));
    note.textContent = lay === "wysiwyg" ? "Visual edits are sanitized: scripts, styles and event handlers are removed." : "";
    if (lay === "wysiwyg") wys.innerHTML = S.sanitize(getDoc());
    renderPreview();
  }
  function pick(mode, user) {
    if (!MODES[mode]) mode = "text";
    state.mode = mode;
    if (user) state.userPicked = true;
    sel.value = mode;
    if (mode === "markdown" && !user) state.preview = !window.matchMedia("(max-width: 720px)").matches;
    view.dispatch({ effects: langC.reconfigure(MODES[mode].lang()) });
    layout();
  }
  sel.addEventListener("change", () => pick(sel.value, true));
  document.addEventListener("nl:editor-open", () => setTimeout(() => {
    state.userPicked = false;
    state.preview = false;
    pick(detect(nameEl && nameEl.textContent));
    view.scrollDOM.scrollTop = 0;
  }, 0));
  setWrap(false);
  pick(detect(nameEl && nameEl.textContent));

  // ---- unsaved-changes guard ----
  const dirty = () => (window.NL && window.NL.isEditorDirty ? window.NL.isEditorDirty() : false);
  window.addEventListener("beforeunload", (e) => { if (dirty()) { e.preventDefault(); e.returnValue = ""; } });
  const NAV = "#fm-back, .mode-tab, #btn-new-file, .drive-tab, .fav-open, #fm .fm-row__name, #file-list li, .nl-bottom-nav__item, .fm-tree__name";
  document.addEventListener("click", (e) => {
    const t = e.target.closest && e.target.closest(NAV);
    if (!t || !dirty() || wrap.classList.contains("hidden")) return;
    if (t.classList.contains("mode-tab") && t.dataset.mode === "files") return;
    if (!confirm("You have unsaved changes. Leave without saving?")) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true);
  if (window.NL && window.NL.openFile && !window.NL.openFile.__guarded) {
    const orig = window.NL.openFile;
    const guarded = (f) => (dirty() && !confirm("You have unsaved changes. Open another file without saving?")) ? undefined : orig(f);
    guarded.__guarded = true;
    window.NL.openFile = guarded;
  }
  window.NLEditor = { pick, view, mode: () => state.mode, layout: () => state.layout, setWrap, detect };
}
