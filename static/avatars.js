/* Chat avatars (av1). Owner-only map from /api/avatars; initials + deterministic
   colour fallback (FNV-1a, mirrored in avatars.py). Click an avatar to set its picture. */
(function () {
  "use strict";
  let map = {};
  let loaded = null;
  const listeners = [];

  function keyFor(name) {
    let s = String(name || "").trim();
    const m = s.match(/\(([^()]+)\)\s*$/);
    if (m) s = m[1];
    s = s.replace(/^[\[\] ]+|[\[\] ]+$/g, "").toLowerCase();
    return s.replace(/[^a-z0-9_.-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 48);
  }
  function initials(name) {
    let s = String(name || "").trim();
    const m = s.match(/\(([^()]+)\)\s*$/);
    if (m) s = m[1];
    const w = s.split(/[^A-Za-z0-9]+/).filter(Boolean);
    if (!w.length) return "?";
    if (w.length === 1) return w[0].length > 1 ? w[0][0].toUpperCase() + w[0][1].toLowerCase() : w[0].toUpperCase();
    return (w[0][0] + w[1][0]).toUpperCase();
  }
  function hueFor(name) {
    let h = 0x811c9dc5;
    const bytes = new TextEncoder().encode(keyFor(name));
    for (const b of bytes) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; }
    return h % 360;
  }
  /* Who sent this message: explicit from, "[Agent] text" (Council/A2A), owner, or the room's bot. */
  function senderFor(msg, roomTitle) {
    if (msg.from) return String(msg.from);
    const m = /^\[([A-Za-z0-9_.-]{1,64})\]\s/.exec(msg.text || "");
    if (m) return m[1];
    if (msg.role === "user") return "John";
    const t = String(roomTitle || "Assistant");
    const p = t.match(/\(([^()]+)\)\s*$/);
    return p ? p[1] : t;
  }
  function info(name) {
    const k = keyFor(name);
    const e = map[k] || {};
    return {
      key: k, name: e.name || name,
      initials: e.initials || initials(name),
      url: e.url || null,
      bg: e.color || `hsl(${hueFor(name)} 55% 42%)`,
    };
  }
  function paint(el, name) {
    const i = info(name);
    el.textContent = "";
    el.style.background = i.bg;
    el.title = i.name;
    el.setAttribute("aria-label", i.name);
    if (i.url) {
      const img = document.createElement("img");
      img.alt = ""; img.src = i.url; img.loading = "lazy"; img.decoding = "async";
      img.onerror = () => { img.remove(); el.textContent = i.initials; };
      el.appendChild(img);
    } else {
      el.textContent = i.initials;
    }
  }
  function el(name) {
    const a = document.createElement("button");
    a.type = "button";
    a.className = "chat-avatar";
    a.dataset.sender = keyFor(name);
    a.dataset.name = name;
    paint(a, name);
    a.addEventListener("click", () => openEditor(name));
    return a;
  }
  function repaintAll() {
    document.querySelectorAll(".chat-avatar[data-name]").forEach((a) => paint(a, a.dataset.name));
  }
  async function load(force) {
    if (loaded && !force) return loaded;
    loaded = fetch("/api/avatars", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : { avatars: {} }))
      .then((j) => { map = j.avatars || {}; repaintAll(); listeners.forEach((f) => f()); return map; })
      .catch(() => map);
    return loaded;
  }

  function openEditor(name) {
    const i = info(name);
    let dlg = document.getElementById("avatar-editor");
    if (dlg) dlg.remove();
    dlg = document.createElement("dialog");
    dlg.id = "avatar-editor";
    dlg.className = "avatar-editor";
    dlg.innerHTML = `<form method="dialog">
      <h3>Avatar</h3>
      <div class="avatar-editor-row"><span class="chat-avatar lg" aria-hidden="true"></span>
        <label>Name <input name="name" maxlength="64" required></label></div>
      <label>Picture (PNG, JPG, WebP, GIF, up to 512 KB) <input name="file" type="file" accept="image/png,image/jpeg,image/webp,image/gif"></label>
      <label>Fallback colour <input name="color" type="color"></label>
      <p class="avatar-editor-msg" role="status"></p>
      <menu><button value="cancel" formnovalidate>Cancel</button>
        ${i.url ? '<button type="button" data-act="clear">Remove picture</button>' : ""}
        <button type="submit" value="save" class="primary">Save</button></menu></form>`;
    document.body.appendChild(dlg);
    const f = dlg.querySelector("form");
    paint(dlg.querySelector(".chat-avatar"), name);
    f.name.value = i.name;
    if (/^#/.test(i.bg)) f.color.value = i.bg;
    const msgEl = dlg.querySelector(".avatar-editor-msg");
    async function post(body) {
      const f2 = window.NL && window.NL.stepUpFetch ? window.NL.stepUpFetch : fetch;
      const r = await f2("/api/avatars/set", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) {
        msgEl.textContent = j.error === "step_up_required"
          ? "Confirm it's you first (step-up), then try again." : "Could not save: " + (j.error || r.status);
        return false;
      }
      await load(true); dlg.close(); return true;
    }
    const clear = dlg.querySelector('[data-act="clear"]');
    if (clear) clear.onclick = () => post({ key: i.key, name: f.name.value, remove_image: true });
    f.addEventListener("submit", async (ev) => {
      if (ev.submitter && ev.submitter.value === "cancel") return;
      ev.preventDefault();
      const body = { key: i.key, name: f.name.value.trim() };
      if (f.color.value) body.color = f.color.value;
      const file = f.file.files && f.file.files[0];
      if (file) {
        if (file.size > 512 * 1024) { msgEl.textContent = "Picture is over 512 KB."; return; }
        body.image_b64 = await new Promise((res) => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.readAsDataURL(file); });
      }
      post(body);
    });
    dlg.addEventListener("close", () => dlg.remove());
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute("open", "");
  }

  const api = { keyFor, initials, hueFor, senderFor, info, el, load, repaintAll, onLoad: (f) => listeners.push(f) };
  if (typeof window !== "undefined") window.NullinkAvatars = api;
  if (typeof module !== "undefined") module.exports = api;
})();
