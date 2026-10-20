(function () {
  const $ = (id) => document.getElementById(id), LIMIT = 200;
  let offset = 0, total = 0, labelsLoaded = false;
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const fmt = new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", month: "short", day: "numeric",
    hour: "numeric", minute: "2-digit", second: "2-digit" });
  const et = (ts) => ts ? fmt.format(new Date(ts * 1000)) + " ET" : "";
  function tone(l) {
    if (/Denied|Rejected|Bad signature|failed|blocked|Wrong/i.test(l)) return "t-bad";
    if (/Approved|PIN used|PIN sent|extended/i.test(l)) return "t-ok";
    if (/expired|Ended|Closed|warning|limited/i.test(l)) return "t-warn";
    return "";
  }
  function params(extra) {
    const p = new URLSearchParams();
    for (const [k, id] of [["q", "q"], ["request_id", "rid"], ["event", "ev"], ["from", "from"], ["to", "to"]]) {
      const v = $(id).value.trim(); if (v) p.set(k, v);
    }
    for (const k in extra || {}) p.set(k, extra[k]);
    return p;
  }
  function row(r, grouped) {
    const det = [r.outcome, r.session_id && ("session " + r.session_id), r.method && (r.method + " " + (r.path || "")),
      r.error, r.count != null && ("count " + r.count), r.extensions && ("ext " + r.extensions), r.detail].filter(Boolean).join(" · ");
    return `<tr class="ev${grouped ? " g-" + esc(r.request_id || "none") : ""}"><td>${esc(et(r.ts))}</td>` +
      `<td><span class="tag ${tone(r.label)}">${esc(r.label)}</span></td><td class="mono">${esc(r.request_id || "")}</td>` +
      `<td>${esc(r.name || "")}</td><td class="mono">${esc(r.ip || "")}</td><td>${esc(r.actor || "")}</td>` +
      `<td>${esc(r.scope || "")}</td><td class="mono">${esc(det)}</td></tr>`;
  }
  async function load() {
    $("meta").textContent = "Loading…";
    const res = await fetch("/api/guest/audit?" + params($("group").value === "1" ? { limit: 5000, offset: 0 } : { limit: LIMIT, offset }), { credentials: "same-origin" });
    if (!res.ok) { $("meta").textContent = res.status === 401 ? "Sign in to Nullink as the owner first." : "Not allowed (" + res.status + ")."; $("tb").innerHTML = ""; return; }
    const d = await res.json(); total = d.total;
    if (!labelsLoaded) { labelsLoaded = true; for (const l of d.labels) { const o = document.createElement("option"); o.value = l; o.textContent = l; $("ev").appendChild(o); } }
    const grouped = $("group").value === "1";
    let html = "";
    if (grouped) {
      const order = [], by = {};
      for (const r of d.rows) { const k = r.request_id || ""; if (!(k in by)) { by[k] = []; order.push(k); } by[k].push(r); }
      for (const k of order) {
        const q = d.requests[k] || {}, rs = by[k];
        const title = k ? `${k} · ${q.name || rs.find((x) => x.name)?.name || "Guest"}` : "Not tied to a request";
        const st = k ? `${q.status || ""}${q.ip ? " · from " + q.ip : ""}${q.redeemed_ip ? " · used from " + q.redeemed_ip : ""}` : "";
        html += `<tr class="grp" data-g="${esc(k || "none")}"><td colspan="8">▸ ${esc(title)} <span class="st">— ${rs.length} event${rs.length > 1 ? "s" : ""}, latest ${esc(et(rs[0].ts))}${st ? " · " + esc(st) : ""}</span></td></tr>`;
        html += rs.map((r) => row(r, true).replace('class="ev', 'class="ev hidden')).join("");
      }
    } else html = d.rows.map((r) => row(r, false)).join("");
    $("tb").innerHTML = html || `<tr><td colspan="8">No matching events.</td></tr>`;
    $("meta").textContent = `${total} event${total === 1 ? "" : "s"} · newest first · PINs are never shown in full`;
    $("pg").textContent = total ? `${offset + 1}–${Math.min(offset + LIMIT, total)} of ${total}` : "";
    const g1 = grouped; $("prev").disabled = g1 || offset === 0; $("next").disabled = g1 || offset + LIMIT >= total;
    if (g1) $("pg").textContent = total ? `all ${total} (grouped)` : "";
  }
  $("tb").addEventListener("click", (e) => {
    const g = e.target.closest("tr.grp"); if (!g) return;
    const rows = document.querySelectorAll("tr.g-" + CSS.escape(g.dataset.g)); const open = rows[0] && rows[0].classList.contains("hidden");
    rows.forEach((r) => r.classList.toggle("hidden", !open));
    g.firstElementChild.innerHTML = g.firstElementChild.innerHTML.replace(open ? "▸" : "▾", open ? "▾" : "▸");
  });
  $("apply").addEventListener("click", () => { offset = 0; load(); });
  $("group").addEventListener("change", load);
  for (const id of ["q", "rid"]) $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") { offset = 0; load(); } });
  $("prev").addEventListener("click", () => { offset = Math.max(0, offset - LIMIT); load(); });
  $("next").addEventListener("click", () => { offset += LIMIT; load(); });
  $("csv").addEventListener("click", () => { location.href = "/api/guest/audit?" + params({ format: "csv" }); });
  const u = new URLSearchParams(location.search); if (u.get("request_id")) $("rid").value = u.get("request_id");
  load();
})();
