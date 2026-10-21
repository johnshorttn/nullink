/* Nullink HTML sanitizer (ed1). Allowlist-based: unknown tags are unwrapped (text kept),
   dangerous containers are dropped entirely, attributes are allowlisted per tag, every on*
   handler is removed, and URLs must be http(s)/mailto/relative (images may also be data:image
   raster). Used for every WYSIWYG render and HTML/Markdown preview. Previews additionally run
   in a sandboxed iframe with no scripts. */
(function (root) {
  "use strict";
  const DROP = new Set(["script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "noscript",
    "template", "link", "meta", "base", "form", "input", "button", "select", "textarea", "option", "svg", "math",
    "title", "head", "audio", "video", "source", "track", "canvas", "portal", "dialog"]);
  const ALLOW = new Set(["a", "abbr", "b", "blockquote", "br", "caption", "code", "col", "colgroup", "dd", "del", "details",
    "div", "dl", "dt", "em", "figcaption", "figure", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "kbd",
    "li", "mark", "ol", "p", "pre", "q", "s", "small", "span", "strike", "strong", "sub", "summary", "sup", "table",
    "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul", "font", "center", "section", "article", "header", "footer",
    "main", "nav", "aside", "time"]);
  const GLOBAL_ATTRS = new Set(["title", "lang", "dir", "class", "align"]);
  const TAG_ATTRS = {
    a: new Set(["href", "name", "target", "rel"]),
    img: new Set(["src", "alt", "width", "height"]),
    td: new Set(["colspan", "rowspan"]), th: new Set(["colspan", "rowspan", "scope"]),
    col: new Set(["span"]), colgroup: new Set(["span"]), ol: new Set(["start", "type"]),
    font: new Set(["color", "size"]), time: new Set(["datetime"]), details: new Set(["open"]),
  };
  const URL_ATTRS = new Set(["href", "src"]);

  function safeUrl(raw, isImg) {
    const v = String(raw || "").replace(/[\u0000-\u0020\u007f-\u009f]+/g, "");
    if (!v) return null;
    const m = /^([a-z][a-z0-9+.-]*):/i.exec(v);
    if (!m) return /^(\/\/)/.test(v) ? null : String(raw).trim(); // relative/anchor OK; no protocol-relative
    const scheme = m[1].toLowerCase();
    if (scheme === "http" || scheme === "https" || (!isImg && scheme === "mailto")) return String(raw).trim();
    if (isImg && /^data:image\/(png|gif|jpe?g|webp);base64,[a-z0-9+/=\s]+$/i.test(v)) return v;
    return null;
  }

  function cleanNode(node, doc) {
    for (const child of Array.from(node.childNodes)) {
      if (child.nodeType === 3) continue; // text
      if (child.nodeType !== 1) { child.remove(); continue; } // comments, PIs, etc.
      const tag = child.tagName.toLowerCase();
      if (DROP.has(tag)) { child.remove(); continue; }
      if (!ALLOW.has(tag)) {
        cleanNode(child, doc);
        while (child.firstChild) node.insertBefore(child.firstChild, child);
        child.remove();
        continue;
      }
      for (const attr of Array.from(child.attributes)) {
        const name = attr.name.toLowerCase();
        const ok = GLOBAL_ATTRS.has(name) || (TAG_ATTRS[tag] && TAG_ATTRS[tag].has(name));
        if (!ok || name.startsWith("on")) { child.removeAttribute(attr.name); continue; }
        if (URL_ATTRS.has(name)) {
          const u = safeUrl(attr.value, tag === "img");
          if (u == null) child.removeAttribute(attr.name); else child.setAttribute(name, u);
        }
      }
      if (tag === "a" && child.getAttribute("target")) { child.setAttribute("target", "_blank"); child.setAttribute("rel", "noopener noreferrer"); }
      cleanNode(child, doc);
    }
  }

  function sanitize(html, DOMParserImpl) {
    const P = DOMParserImpl || root.DOMParser;
    const doc = new P().parseFromString("<!doctype html><body>" + String(html == null ? "" : html), "text/html");
    cleanNode(doc.body, doc);
    return doc.body.innerHTML;
  }

  /* Full preview document for a sandboxed iframe (sandbox="" => no scripts, no same-origin). */
  function previewDoc(cleanHtml, dark) {
    const bg = dark ? "#0f1115" : "#fff", fg = dark ? "#e6e6e6" : "#111";
    return "<!doctype html><html><head><meta charset=utf-8>" +
      "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src https: http: data:; style-src 'unsafe-inline'\">" +
      `<style>body{font:15px/1.55 system-ui,sans-serif;margin:16px;background:${bg};color:${fg};word-wrap:break-word}` +
      "img{max-width:100%}table{border-collapse:collapse}td,th{border:1px solid #8885;padding:4px 8px}" +
      "pre{overflow:auto;background:#8881;padding:8px;border-radius:6px}a{color:#4b8bf5}</style></head><body>" +
      cleanHtml + "</body></html>";
  }

  const api = { sanitize, previewDoc, safeUrl };
  if (typeof module === "object" && module.exports) module.exports = api;
  root.NLSanitize = api;
})(typeof window !== "undefined" ? window : globalThis);
