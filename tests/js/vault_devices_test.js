// Run: node tests/js/vault_devices_test.js  (driven by tests/test_vault_devices_ui.py)
"use strict";
const assert = require("assert");
const V = require("../../static/vault-devices.js");
let n = 0;
const tests = [];
const t = (name, fn) => tests.push([name, fn]);

// ---- tiny fake DOM (enough for vault-devices.js) ----
class CL { constructor() { this.s = new Set(); } add(c) { this.s.add(c); } remove(c) { this.s.delete(c); }
  contains(c) { return this.s.has(c); } toggle(c) { this.s.has(c) ? this.s.delete(c) : this.s.add(c); } }
class El {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.classList = new CL();
    this._text = ""; this.value = ""; this.disabled = false; this.checked = false; this.l = {}; this.id = ""; }
  set className(v) { this.classList = new CL(); String(v).split(/\s+/).filter(Boolean).forEach((c) => this.classList.add(c)); }
  get className() { return [...this.classList.s].join(" "); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  appendChild(c) { this.children.push(c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(ev, fn) { (this.l[ev] = this.l[ev] || []).push(fn); }
  fire(ev, arg) { (this.l[ev] || []).forEach((fn) => fn(arg || {})); }
  click() { if (!this.disabled) this.fire("click"); }
  all(pred, out = []) { if (pred(this)) out.push(this); this.children.forEach((c) => c.all(pred, out)); return out; }
}
function makeDoc() {
  const ids = {};
  const mk = (id, tag = "div") => { const e = new El(tag); e.id = id; ids[id] = e; return e; };
  const section = mk("vault-devices", "details"); section.classList.add("hidden");
  ["vault-devices-list", "vault-devices-status", "vault-devices-confirm", "vault-devices-hint"].forEach((i) => mk(i));
  ["vault-devices-revoke-all", "vault-devices-revoke-selected", "vault-devices-refresh"].forEach((i) => mk(i, "button"));
  return { getElementById: (i) => ids[i] || null, createElement: (tag) => new El(tag), ids };
}
const resp = (status, js) => ({ status, ok: status >= 200 && status < 300, json: async () => js });
const DEV = (id, status = "active", seen = "2026-11-14T04:02:59+00:00") =>
  ({ device_id: id, status, model: "Pixel 9", manufacturer: "Google", last_seen_at: seen });
const A = "dev_72bd5a8854d6358f", B = "dev_c7e968516119fb88";

function server(opts = {}) {
  const calls = [];
  let devs = opts.devices || [DEV(A), DEV(B, "active", "2026-11-12T22:54:31+00:00")];
  const f = async (url, o = {}) => {
    calls.push({ url, o });
    if (url === "/api/me") return resp(200, { authenticated: true, auth_type: opts.authType || "session" });
    if (url === "/api/vault/devices") return opts.listStatus ? resp(opts.listStatus, { error: "guest_forbidden" }) : resp(200, { cap: 2, devices: devs });
    const body = JSON.parse(o.body || "{}");
    if (opts.reply) return opts.reply(url, body);
    const m = url.match(/^\/api\/vault\/devices\/(dev_[0-9a-f]{16})\/revoke$/);
    if (m) { devs = devs.map((d) => d.device_id === m[1] ? { ...d, status: "revoked" } : d); return resp(200, { ok: true, device_id: m[1], status: "revoked" }); }
    if (url === "/api/vault/devices/revoke-batch") {
      const ids = body.all ? devs.filter((d) => d.status !== "revoked").map((d) => d.device_id) : body.device_ids;
      devs = devs.map((d) => ids.includes(d.device_id) ? { ...d, status: "revoked" } : d);
      return resp(200, { ok: true, revoked: ids.length, results: ids.map((i) => ({ device_id: i, status: "revoked" })) });
    }
    return resp(404, {});
  };
  return { f, calls };
}
const buttons = (doc, text) => doc.ids["vault-devices-list"].all((e) => e.tagName === "BUTTON" && e.textContent === text);
const inputs = (root) => root.all((e) => e.tagName === "INPUT" && e.classList.contains("vault-devices-code"));

// ---- pure helpers ----
t("last seen is shown in ET", () => {
  assert.strictEqual(V.fmtET("2026-11-14T04:02:59+00:00"), "Nov 13, 2026, 11:02 PM ET");
  assert.strictEqual(V.fmtET(null), "never");
});
t("messages: wrong code with attempts left, locked with retry time", () => {
  assert.strictEqual(V.errorText(401, { error: "wrong_code", attempts_left: 4 }), "Wrong or expired code. 4 attempts left before a lockout. Wait for a new code and try again.");
  assert.strictEqual(V.errorText(401, { error: "wrong_code", attempts_left: 1 }).includes("1 attempt left"), true);
  assert.strictEqual(V.errorText(429, { error: "locked", retry_after_sec: 900 }), "Too many wrong codes: locked. Try again in 15 min.");
  assert.ok(V.singleResultText(200, { ok: true, device_id: A }).text.startsWith("Revoked " + A));
  const b = V.batchResultText(200, { ok: true, results: [{ device_id: A, status: "revoked" }, { device_id: B, status: "already_revoked" }] });
  assert.strictEqual(b.text, `Revoked 1: ${A}. Already revoked: ${B}.`);
});
t("requests: same-origin cookie, JSON {code}, never an Authorization header", () => {
  const [u, o] = V.singleRequest(A, "123456");
  assert.strictEqual(u, `/api/vault/devices/${A}/revoke`);
  assert.strictEqual(o.method, "POST"); assert.strictEqual(o.credentials, "same-origin");
  assert.deepStrictEqual(JSON.parse(o.body), { code: "123456" });
  assert.ok(!Object.keys(o.headers).some((h) => h.toLowerCase() === "authorization"));
  const [bu, bo] = V.batchRequest([A, "bogus", B], false, "123456");
  assert.strictEqual(bu, "/api/vault/devices/revoke-batch");
  assert.deepStrictEqual(JSON.parse(bo.body), { code: "123456", device_ids: [A, B] });
  assert.deepStrictEqual(JSON.parse(V.batchRequest([], true, "654321")[1].body), { code: "654321", all: true });
  assert.ok(!Object.keys(bo.headers).some((h) => h.toLowerCase() === "authorization"));
  assert.throws(() => V.singleRequest("../x", "123456"));
});
t("hint says each code works once", () => { assert.ok(V.HINT.includes("works once")); assert.ok(V.HINT.includes("wait for the next code")); });

// ---- DOM flows ----
t("owner sees the list; hidden for a guest or a refused list", async () => {
  let doc = makeDoc(); let s = server();
  assert.strictEqual(await V.mount({ doc, fetch: s.f }).refresh(), true);
  assert.ok(!doc.ids["vault-devices"].classList.contains("hidden"));
  const txt = doc.ids["vault-devices-list"].textContent;
  assert.ok(txt.includes(A) && txt.includes(B) && txt.includes("Google Pixel 9") && txt.includes("active") && txt.includes("Last seen Nov 13, 2026, 11:02 PM ET"));
  assert.strictEqual(buttons(doc, "Revoke").length, 2);
  for (const o of [{ authType: "guest" }, { listStatus: 403 }]) {
    doc = makeDoc(); s = server(o);
    assert.strictEqual(await V.mount({ doc, fetch: s.f }).refresh(), false);
    assert.ok(doc.ids["vault-devices"].classList.contains("hidden"));
    assert.ok(!s.calls.some((c) => c.url.includes("revoke")));
  }
});
t("Revoke opens an inline numeric one-time-code box; Confirm posts, clears the field, refreshes", async () => {
  const doc = makeDoc(); const s = server();
  const ui = V.mount({ doc, fetch: s.f }); await ui.refresh();
  const li = doc.ids["vault-devices-list"].children[0];
  const form = li.children[1];
  assert.ok(form.classList.contains("hidden"));
  buttons(doc, "Revoke")[0].click();
  assert.ok(!form.classList.contains("hidden"));
  const input = inputs(form)[0];
  assert.strictEqual(input.attrs.inputmode, "numeric");
  assert.strictEqual(input.attrs.autocomplete, "one-time-code");
  input.value = "123456";
  form.all((e) => e.tagName === "BUTTON" && e.textContent === "Confirm")[0].click();
  assert.strictEqual(input.value, "");                       // cleared before the request returns
  await new Promise((r) => setTimeout(r, 10));
  const post = s.calls.find((c) => c.url === `/api/vault/devices/${A}/revoke`);
  assert.ok(post); assert.strictEqual(post.o.credentials, "same-origin");
  assert.ok(!JSON.stringify(post.o.headers).toLowerCase().includes("authorization"));
  assert.ok(doc.ids["vault-devices-status"].textContent.startsWith("Revoked " + A));
  assert.ok(doc.ids["vault-devices-status"].classList.contains("ok"));
  assert.strictEqual(s.calls.filter((c) => c.url === "/api/vault/devices").length, 2);   // list refreshed
  assert.strictEqual(buttons(doc, "Revoke").length, 1);      // A is revoked now: no button
});
t("wrong code and lockout are shown; the field is cleared; nothing refreshed", async () => {
  for (const [st, js, want] of [[401, { error: "wrong_code", attempts_left: 4 }, "4 attempts left"], [429, { error: "locked", retry_after_sec: 1800 }, "Try again in 30 min"]]) {
    const doc = makeDoc(); const s = server({ reply: () => resp(st, js) });
    const ui = V.mount({ doc, fetch: s.f }); await ui.refresh();
    buttons(doc, "Revoke")[0].click();
    const form = doc.ids["vault-devices-list"].children[0].children[1];
    const input = inputs(form)[0]; input.value = "000000";
    form.all((e) => e.textContent === "Confirm")[0].click();
    await new Promise((r) => setTimeout(r, 10));
    assert.ok(doc.ids["vault-devices-status"].textContent.includes(want));
    assert.ok(doc.ids["vault-devices-status"].classList.contains("err"));
    assert.strictEqual(input.value, "");
    assert.strictEqual(s.calls.filter((c) => c.url === "/api/vault/devices").length, 1);
  }
});
t("a non-6-digit code is never sent", async () => {
  const doc = makeDoc(); const s = server();
  const ui = V.mount({ doc, fetch: s.f }); await ui.refresh();
  buttons(doc, "Revoke")[0].click();
  const form = doc.ids["vault-devices-list"].children[0].children[1];
  inputs(form)[0].value = "12a4";
  form.all((e) => e.textContent === "Confirm")[0].click();
  await new Promise((r) => setTimeout(r, 10));
  assert.ok(!s.calls.some((c) => c.url.includes("revoke")));
  assert.strictEqual(inputs(form)[0].value, "");
});
t("Revoke all: confirm step lists the devices, ONE code, batch call with all:true", async () => {
  const doc = makeDoc(); const s = server();
  const ui = V.mount({ doc, fetch: s.f }); await ui.refresh();
  doc.ids["vault-devices-revoke-all"].click();
  const c = doc.ids["vault-devices-confirm"];
  assert.ok(!c.classList.contains("hidden"));
  assert.ok(c.textContent.includes("These 2 devices will be revoked"));
  assert.ok(c.textContent.includes(A) && c.textContent.includes(B));
  const input = inputs(c)[0]; input.value = "654321";
  c.all((e) => e.id === "vault-devices-batch-confirm")[0].click();
  assert.strictEqual(input.value, "");
  await new Promise((r) => setTimeout(r, 10));
  const posts = s.calls.filter((c2) => c2.url.includes("revoke"));
  assert.strictEqual(posts.length, 1);
  assert.deepStrictEqual(JSON.parse(posts[0].o.body), { code: "654321", all: true });
  assert.ok(doc.ids["vault-devices-status"].textContent.startsWith("Revoked 2:"));
  assert.strictEqual(buttons(doc, "Revoke").length, 0);
  assert.ok(doc.ids["vault-devices-revoke-all"].disabled);
});
t("Revoke selected: checkboxes pick the set; the confirm lists only those", async () => {
  const doc = makeDoc(); const s = server();
  const ui = V.mount({ doc, fetch: s.f }); await ui.refresh();
  assert.ok(doc.ids["vault-devices-revoke-selected"].disabled);
  const cb = doc.ids["vault-devices-list"].all((e) => e.tagName === "INPUT" && e.type === "checkbox");
  assert.strictEqual(cb.length, 2);
  cb[1].checked = true; cb[1].fire("change");
  assert.strictEqual(doc.ids["vault-devices-revoke-selected"].textContent, "Revoke selected (1)");
  doc.ids["vault-devices-revoke-selected"].click();
  const c = doc.ids["vault-devices-confirm"];
  assert.ok(c.textContent.includes("These 1 device will be revoked") && c.textContent.includes(B) && !c.textContent.includes(A));
  inputs(c)[0].value = "111111";
  c.all((e) => e.id === "vault-devices-batch-confirm")[0].click();
  await new Promise((r) => setTimeout(r, 10));
  const post = s.calls.find((c2) => c2.url === "/api/vault/devices/revoke-batch");
  assert.deepStrictEqual(JSON.parse(post.o.body), { code: "111111", device_ids: [B] });
});
t("the code never reaches console or storage", () => {
  const src = require("fs").readFileSync(require("path").join(__dirname, "../../static/vault-devices.js"), "utf8");
  for (const bad of ["console.", "localStorage", "sessionStorage", "document.cookie", "Authorization"]) {
    if (bad === "Authorization") { assert.ok(!/headers:\s*\{[^}]*Authorization/.test(src)); continue; }
    assert.ok(!src.includes(bad), bad);
  }
});

(async () => {
  for (const [name, fn] of tests) {
    try { await fn(); n++; } catch (e) { console.error("FAIL " + name + "\n" + (e && e.stack)); process.exit(1); }
  }
  console.log("OK " + n);
})();
