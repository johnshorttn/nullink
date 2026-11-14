/* Nullink Vault -> Devices (2026-11-14, John: "Build the Revoke button on the vault page", "Add revoke all to
   batch revoke"). Lists GET /api/vault/devices for the owner session; revokes one device
   (POST /api/vault/devices/<id>/revoke) or several with ONE code (POST /api/vault/devices/revoke-batch).
   Same-origin cookie only, never an Authorization header. The code is never logged or stored: the field is
   cleared before each request is sent. UMD: window.NLVaultDevices in the page, require() in tests. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.NLVaultDevices = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  const ID_RE = /^dev_[0-9a-f]{16}$/;
  const HINT = "Each authenticator code works once. After revoking one device, wait for the next code before the next device. " +
    "Revoke all / Revoke selected uses a single code for the whole set.";

  function fmtET(iso) {
    const t = Date.parse(iso || "");
    if (isNaN(t)) return "never";
    const s = new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", month: "short", day: "numeric",
      year: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(t));
    return s + " ET";
  }
  const isCode = (s) => /^\d{6}$/.test(String(s || ""));
  const isActive = (d) => d && d.status !== "revoked";
  const label = (d) => `${d.device_id}${d.model ? " (" + [d.manufacturer, d.model].filter(Boolean).join(" ") + ")" : ""}`;

  function errorText(status, js) {
    const e = (js && js.error) || "";
    if (e === "wrong_code") {
      const n = js.attempts_left;
      return `Wrong or expired code.${n != null ? ` ${n} attempt${n === 1 ? "" : "s"} left before a lockout.` : ""} Wait for a new code and try again.`;
    }
    if (e === "locked") {
      const s = Number(js.retry_after_sec) || 0;
      return `Too many wrong codes: locked. Try again in ${Math.max(1, Math.ceil(s / 60))} min.`;
    }
    if (e === "unauthorized" || status === 401) return "Your session ended. Sign in again, then retry.";
    if (e === "guest_forbidden") return "Guests can't revoke devices.";
    if (e === "bad_origin" || e === "forbidden") return "Refused: open Nullink at its own address and retry.";
    if (e === "not_found") return "That device is not registered.";
    if (e === "no_devices") return "No active devices to revoke.";
    if (e === "totp_not_enabled") return "Turn on the authenticator app in Nullink settings first.";
    if (e === "invalid_code_format") return "Enter the 6-digit code.";
    return `Revoke failed (${e || "HTTP " + status}).`;
  }

  function singleResultText(status, js) {
    if (status === 200 && js && js.ok) return { ok: true, text: `Revoked ${js.device_id}. It is told to wipe the next time it connects.` };
    return { ok: false, text: errorText(status, js) };
  }

  function batchResultText(status, js) {
    if (!(status === 200 && js && js.ok)) return { ok: false, text: errorText(status, js) };
    const by = (k) => (js.results || []).filter((r) => r.status === k).map((r) => r.device_id);
    const parts = [];
    const rv = by("revoked"), already = by("already_revoked"), nf = by("not_found");
    if (rv.length) parts.push(`Revoked ${rv.length}: ${rv.join(", ")}.`);
    if (already.length) parts.push(`Already revoked: ${already.join(", ")}.`);
    if (nf.length) parts.push(`Not found: ${nf.join(", ")}.`);
    return { ok: true, text: parts.join(" ") || "Nothing to revoke." };
  }

  /** Request builders: same-origin credentials, JSON body, no Authorization header. */
  function singleRequest(id, code) {
    if (!ID_RE.test(id)) throw new Error("bad device id");
    return [`/api/vault/devices/${id}/revoke`, { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: String(code) }) }];
  }
  function batchRequest(ids, all, code) {
    const body = all ? { code: String(code), all: true } : { code: String(code), device_ids: ids.filter((i) => ID_RE.test(i)) };
    return ["/api/vault/devices/revoke-batch", { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }];
  }

  async function readJson(r) { try { return await r.json(); } catch (_) { return {}; } }

  function el(doc, tag, cls, text) {
    const e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function codeInput(doc, id) {
    const i = el(doc, "input", "vault-devices-code");
    i.type = "text";
    i.setAttribute("inputmode", "numeric");
    i.setAttribute("autocomplete", "one-time-code");
    i.setAttribute("pattern", "[0-9]{6}");
    i.setAttribute("maxlength", "6");
    i.setAttribute("aria-label", "6-digit authenticator code");
    i.placeholder = "6-digit code";
    i.id = id;
    return i;
  }
  /** Reads the code and clears the field at once: the code is never kept, logged or stored. */
  function takeCode(input) { const c = String(input.value || "").replace(/\s+/g, ""); input.value = ""; return c; }

  /**
   * Wire the section. ids: section, list, status, actions area, confirm area. deps: { fetch, doc }.
   * Returns { refresh } (and internals for tests).
   */
  function mount(deps) {
    const doc = deps.doc, f = deps.fetch;
    const section = doc.getElementById("vault-devices");
    const list = doc.getElementById("vault-devices-list");
    const statusEl = doc.getElementById("vault-devices-status");
    const confirmEl = doc.getElementById("vault-devices-confirm");
    const allBtn = doc.getElementById("vault-devices-revoke-all");
    const selBtn = doc.getElementById("vault-devices-revoke-selected");
    const refreshBtn = doc.getElementById("vault-devices-refresh");
    const hintEl = doc.getElementById("vault-devices-hint");
    if (!section || !list) return null;
    if (hintEl) hintEl.textContent = HINT;
    let devices = [];
    const selected = new Set();
    let busy = false;

    const setStatus = (text, kind) => {
      statusEl.textContent = text || "";
      statusEl.className = "vault-devices-status" + (kind ? " " + kind : "");
    };
    const hide = () => { section.classList.add("hidden"); };
    const clearConfirm = () => { confirmEl.textContent = ""; confirmEl.classList.add("hidden"); };

    function updateBatchButtons() {
      const active = devices.filter(isActive);
      allBtn.disabled = busy || active.length === 0;
      selBtn.disabled = busy || selected.size === 0;
      selBtn.textContent = selected.size ? `Revoke selected (${selected.size})` : "Revoke selected";
    }

    function render() {
      list.textContent = "";
      devices.forEach((d) => {
        const li = el(doc, "li", "vault-device" + (isActive(d) ? "" : " revoked"));
        const top = el(doc, "div", "vault-device-row");
        if (isActive(d)) {
          const cb = el(doc, "input", "vault-device-check");
          cb.type = "checkbox";
          cb.checked = selected.has(d.device_id);
          cb.setAttribute("aria-label", "Select " + d.device_id);
          cb.addEventListener("change", () => { cb.checked ? selected.add(d.device_id) : selected.delete(d.device_id); updateBatchButtons(); });
          top.appendChild(cb);
        }
        const info = el(doc, "div", "vault-device-info");
        info.appendChild(el(doc, "code", "vault-device-id", d.device_id));
        info.appendChild(el(doc, "span", "vault-device-model", [d.manufacturer, d.model].filter(Boolean).join(" ") || "unknown model"));
        info.appendChild(el(doc, "span", "vault-device-status status-" + (d.status || "unknown"), d.status || "unknown"));
        info.appendChild(el(doc, "span", "vault-device-seen", "Last seen " + fmtET(d.last_seen_at)));
        top.appendChild(info);
        const form = el(doc, "div", "vault-device-form hidden");
        if (isActive(d)) {
          const rb = el(doc, "button", "ghost tiny fm-danger vault-device-revoke", "Revoke");
          rb.type = "button";
          rb.disabled = busy;
          rb.addEventListener("click", () => { form.classList.toggle("hidden"); });
          top.appendChild(rb);
          const input = codeInput(doc, "vault-code-" + d.device_id);
          const ok = el(doc, "button", "accent-btn tiny vault-device-confirm", "Confirm");
          ok.type = "button";
          const cancel = el(doc, "button", "ghost tiny", "Cancel");
          cancel.type = "button";
          cancel.addEventListener("click", () => { input.value = ""; form.classList.add("hidden"); });
          form.appendChild(el(doc, "span", "hint", `Code to revoke ${d.device_id}:`));
          form.appendChild(input); form.appendChild(ok); form.appendChild(cancel);
          ok.addEventListener("click", () => revokeOne(d.device_id, input));
          input.addEventListener("keydown", (ev) => { if (ev && ev.key === "Enter") revokeOne(d.device_id, input); });
        }
        li.appendChild(top); li.appendChild(form);
        list.appendChild(li);
      });
      if (!devices.length) list.appendChild(el(doc, "li", "hint", "No devices registered."));
      updateBatchButtons();
    }

    async function refresh() {
      try {
        const me = await f("/api/me", { credentials: "same-origin" });
        const mj = await readJson(me);
        if (!me.ok || mj.auth_type !== "session") { hide(); return false; }   // owner cookie session only
        const r = await f("/api/vault/devices", { credentials: "same-origin" });
        if (!r.ok) { hide(); return false; }                                  // guest / flag off / signed out
        const js = await readJson(r);
        devices = Array.isArray(js.devices) ? js.devices : [];
        for (const id of Array.from(selected)) if (!devices.some((d) => d.device_id === id && isActive(d))) selected.delete(id);
        section.classList.remove("hidden");
        render();
        return true;
      } catch (_) { hide(); return false; }
    }

    async function revokeOne(id, input) {
      if (busy) return;
      const code = takeCode(input);
      if (!isCode(code)) { setStatus("Enter the 6-digit code from your authenticator app.", "err"); return; }
      busy = true; updateBatchButtons(); setStatus("Revoking " + id + "…");
      try {
        const [url, opt] = singleRequest(id, code);
        const r = await f(url, opt);
        const res = singleResultText(r.status, await readJson(r));
        setStatus(res.text, res.ok ? "ok" : "err");
        if (res.ok) { selected.delete(id); await refresh(); }
      } catch (_) { setStatus("Network error. Nothing was changed on this page; check the list and retry.", "err"); }
      finally { busy = false; updateBatchButtons(); }
    }

    function openBatch(all) {
      const targets = all ? devices.filter(isActive) : devices.filter((d) => selected.has(d.device_id) && isActive(d));
      if (!targets.length) { setStatus("No active devices to revoke.", "err"); return; }
      confirmEl.textContent = "";
      confirmEl.classList.remove("hidden");
      confirmEl.appendChild(el(doc, "p", "vault-devices-confirm-title",
        `These ${targets.length} device${targets.length === 1 ? "" : "s"} will be revoked (each is told to wipe at its next contact):`));
      const ul = el(doc, "ul", "vault-devices-confirm-list");
      targets.forEach((d) => ul.appendChild(el(doc, "li", null, label(d))));
      confirmEl.appendChild(ul);
      confirmEl.appendChild(el(doc, "p", "hint", "One authenticator code revokes all of them."));
      const input = codeInput(doc, "vault-code-batch");
      const ok = el(doc, "button", "accent-btn tiny fm-danger", `Confirm revoke (${targets.length})`);
      ok.type = "button"; ok.id = "vault-devices-batch-confirm";
      const cancel = el(doc, "button", "ghost tiny", "Cancel");
      cancel.type = "button";
      cancel.addEventListener("click", () => { input.value = ""; clearConfirm(); });
      ok.addEventListener("click", () => revokeBatch(all, targets.map((d) => d.device_id), input));
      confirmEl.appendChild(input); confirmEl.appendChild(ok); confirmEl.appendChild(cancel);
    }

    async function revokeBatch(all, ids, input) {
      if (busy) return;
      const code = takeCode(input);
      if (!isCode(code)) { setStatus("Enter the 6-digit code from your authenticator app.", "err"); return; }
      busy = true; updateBatchButtons(); setStatus(`Revoking ${ids.length} device${ids.length === 1 ? "" : "s"}…`);
      try {
        const [url, opt] = batchRequest(ids, all, code);
        const r = await f(url, opt);
        const res = batchResultText(r.status, await readJson(r));
        setStatus(res.text, res.ok ? "ok" : "err");
        if (res.ok) { clearConfirm(); selected.clear(); await refresh(); }
      } catch (_) { setStatus("Network error. Check the list and retry.", "err"); }
      finally { busy = false; updateBatchButtons(); }
    }

    allBtn.addEventListener("click", () => openBatch(true));
    selBtn.addEventListener("click", () => openBatch(false));
    if (refreshBtn) refreshBtn.addEventListener("click", () => refresh());
    return { refresh, _state: () => ({ devices, selected, busy }) };
  }

  return { fmtET, isCode, errorText, singleResultText, batchResultText, singleRequest, batchRequest, mount, HINT };
});
