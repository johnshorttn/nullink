/* Bots profile page (bots1). Owner-only: every sender seen in chats with avatar, display
   name and colour. Change picture/name/colour, merge name aliases (Claude + Claude Code).
   Writes go through step-up (authenticator) like the chat avatar editor. */
(function () {
  "use strict";
  const AV = () => window.NullinkAvatars;
  const sfetch = (u, o) => (window.NL && window.NL.stepUpFetch ? window.NL.stepUpFetch(u, o) : fetch(u, o));
  let profiles = [];
  let page = null;

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

  async function post(path, body) {
    const r = await sfetch(path, { method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error === "step_up_required" ? "Confirm it's you (authenticator code) to save." : (j.error || ("HTTP " + r.status)));
    return j;
  }

  function status(t, bad) {
    const s = page && page.querySelector(".bots-status");
    if (s) { s.textContent = t || ""; s.classList.toggle("bad", !!bad); }
  }

  function avatarFor(p) {
    const a = document.createElement("span");
    a.className = "chat-avatar lg";
    a.setAttribute("aria-hidden", "true");
    a.style.background = p.color || `hsl(${p.hue} 55% 42%)`;
    if (p.url) { const i = document.createElement("img"); i.alt = ""; i.src = p.url; a.appendChild(i); }
    else a.textContent = p.initials || "?";
    return a;
  }

  function render() {
    const list = page.querySelector(".bots-list");
    list.textContent = "";
    if (!profiles.length) { list.innerHTML = '<p class="hint">No senders yet.</p>'; return; }
    for (const p of profiles) {
      const card = document.createElement("li");
      card.className = "bot-card";
      card.dataset.key = p.key;
      const others = profiles.filter((o) => o.key !== p.key);
      const names = [...new Set(p.names || [])].filter((n) => AV() && AV().keyFor(n) !== p.key && !(p.aliases || []).includes(AV().keyFor(n)));
      card.innerHTML = `
        <div class="bot-card-head"><span class="bot-av"></span>
          <div class="bot-meta"><strong class="bot-name">${esc(p.name)}</strong>
            <span class="hint">${esc(p.key)} · ${p.count} message${p.count === 1 ? "" : "s"}</span>
            ${p.aliases && p.aliases.length ? `<span class="bot-aliases">${p.aliases.map((a) => `<span class="chip">${esc(a)} <button type="button" data-unmerge="${esc(a)}" aria-label="Unmerge ${esc(a)}" title="Unmerge">×</button></span>`).join("")}</span>` : ""}
            ${names.length ? `<span class="hint">Also seen as: ${names.map(esc).join(", ")}</span>` : ""}
          </div></div>
        <form class="bot-form">
          <label>Display name <input name="name" maxlength="64" required value="${esc(p.name)}"></label>
          <label>Colour <input name="color" type="color" value="${esc(p.color || "#4a6fa5")}"></label>
          <label class="bot-file">Picture (PNG/JPG/WebP/GIF ≤ 512 KB) <input name="file" type="file" accept="image/png,image/jpeg,image/webp,image/gif"></label>
          <div class="bot-actions">
            <button type="submit" class="primary">Save</button>
            ${p.url ? '<button type="button" data-act="clear">Remove picture</button>' : ""}
            <select name="merge" aria-label="Merge into another profile"><option value="">Merge into…</option>
              ${others.map((o) => `<option value="${esc(o.key)}">${esc(o.name)}</option>`).join("")}</select>
          </div>
        </form>`;
      card.querySelector(".bot-av").replaceWith(avatarFor(p));
      const f = card.querySelector("form");
      f.color.addEventListener("input", () => { f.color.dataset.touched = "1"; });
      f.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const body = { key: p.key, name: f.name.value.trim() };
        if (f.color.dataset.touched || p.color) body.color = f.color.value;
        const file = f.file.files && f.file.files[0];
        if (file) {
          if (file.size > 512 * 1024) return status("Picture is over 512 KB.", true);
          if (/svg/i.test(file.type) || /\.svg$/i.test(file.name)) return status("SVG pictures are not allowed.", true);
          body.image_b64 = await new Promise((res) => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.readAsDataURL(file); });
        }
        try { await post("/api/avatars/set", body); status("Saved " + body.name + "."); await refresh(); } catch (e) { status(e.message, true); }
      });
      const clr = card.querySelector('[data-act="clear"]');
      if (clr) clr.onclick = async () => {
        try { await post("/api/avatars/set", { key: p.key, name: f.name.value.trim() || p.name, remove_image: true }); await refresh(); } catch (e) { status(e.message, true); }
      };
      f.merge.onchange = async () => {
        const into = f.merge.value; if (!into) return;
        const tgt = profiles.find((o) => o.key === into);
        if (!window.confirm(`Merge "${p.name}" into "${tgt ? tgt.name : into}"? Messages from both will share one profile.`)) { f.merge.value = ""; return; }
        try { await post("/api/avatars/merge", { into, from: p.key, name: tgt ? tgt.name : into }); status("Merged."); await refresh(); } catch (e) { status(e.message, true); f.merge.value = ""; }
      };
      card.querySelectorAll("[data-unmerge]").forEach((b) => b.onclick = async () => {
        try { await post("/api/avatars/unmerge", { alias: b.dataset.unmerge }); await refresh(); } catch (e) { status(e.message, true); }
      });
      list.appendChild(card);
    }
  }

  async function refresh() {
    const r = await fetch("/api/avatars/senders", { credentials: "include" });
    if (!r.ok) { status("Could not load bots (" + r.status + ").", true); return; }
    profiles = (await r.json()).profiles || [];
    render();
    if (AV()) AV().load(true);
  }

  function open() {
    if (!page) {
      page = document.createElement("section");
      page.id = "bots-page";
      page.className = "bots-page";
      page.setAttribute("role", "dialog");
      page.setAttribute("aria-label", "Bot profiles");
      page.innerHTML = `<header class="bots-head"><button type="button" class="ghost" data-act="close" aria-label="Back">←</button>
        <h2>Bots</h2><span class="hint">Avatars &amp; names for everyone in your chats</span></header>
        <p class="bots-status" role="status" aria-live="polite"></p><ul class="bots-list" role="list"></ul>`;
      document.body.appendChild(page);
      page.querySelector('[data-act="close"]').onclick = close;
    }
    page.hidden = false;
    if (location.hash !== "#bots") history.replaceState(null, "", "#bots");
    refresh();
  }
  function close() {
    if (page) page.hidden = true;
    if (location.hash === "#bots") history.replaceState(null, "", location.pathname + location.search);
  }
  window.addEventListener("keydown", (e) => { if (e.key === "Escape" && page && !page.hidden) close(); });
  window.addEventListener("hashchange", () => { if (location.hash === "#bots") open(); });
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-bots-open]").forEach((b) => b.addEventListener("click", open));
    if (location.hash === "#bots") setTimeout(open, 300);
  });

  const api = { open, close, refresh };
  if (typeof window !== "undefined") window.NullinkBots = api;
})();
