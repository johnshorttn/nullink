/* Nullink Files — sorting + "Latest of similar files" grouping (2026-10-26).
   Pure functions; used by files-manager.js (window.NLFmSort) and by tests (node require). */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.NLFmSort = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  const SORTS = {
    name: "Name",
    ext: "Extension / type",
    added: "Date added",
    created: "Date created",
  };
  const DEFAULT = { key: "name", dir: "asc" };

  function extOf(name) {
    const n = String(name || "").toLowerCase();
    const base = n.split("/").pop();
    const i = base.lastIndexOf(".");
    return i > 0 ? base.slice(i + 1) : "";
  }
  const ts = (s) => { const t = Date.parse(s || ""); return isNaN(t) ? 0 : t; };
  const addedTs = (f) => ts(f.added_at || f.updated_at);
  const createdTs = (f) => ts(f.created_at || f.added_at || f.updated_at);
  const byName = (a, b) => String(a.name || "").localeCompare(String(b.name || ""), undefined, { sensitivity: "base", numeric: true });

  function normSort(s) {
    s = s || {};
    return { key: SORTS[s.key] ? s.key : DEFAULT.key, dir: s.dir === "desc" ? "desc" : "asc" };
  }

  /* Returns a new array. ext: group by extension (files without one last), then name A–Z.
     Dates: ties fall back to name A–Z. dir flips the primary key only. */
  function sortFiles(files, s) {
    const { key, dir } = normSort(s);
    const m = dir === "desc" ? -1 : 1;
    const cmp = {
      name: (a, b) => m * byName(a, b),
      ext: (a, b) => {
        const ea = extOf(a.name), eb = extOf(b.name);
        if (ea !== eb) {
          if (!ea) return 1;
          if (!eb) return -1;
          return m * ea.localeCompare(eb);
        }
        return byName(a, b);
      },
      added: (a, b) => m * (addedTs(a) - addedTs(b)) || byName(a, b),
      created: (a, b) => m * (createdTs(a) - createdTs(b)) || byName(a, b),
    }[key];
    return (files || []).slice().sort(cmp);
  }

  // ---- similar-name grouping ----
  const SEP = /[-_. ]+/;
  function stemOf(name) {
    const base = String(name || "").toLowerCase().split("/").pop();
    const i = base.lastIndexOf(".");
    return i > 0 ? base.slice(0, i) : base;
  }
  /* Lowercase stem with version-like tokens removed: copy suffixes, dates/timestamps,
     git short hashes (7–12 hex with a digit), versions (v1, v1.2.3, 1.2), plain numbers. */
  function normBase(name) {
    let s = stemOf(name);
    s = s.replace(/\s*\(\d+\)\s*$/, "")
      .replace(/[-_ ]*(copy|kopie)(\s*\d+)?$/i, "")
      .replace(/\d{4}[-_.]?\d{2}[-_.]?\d{2}(?:[t_ -]?\d{2}[:.-]?\d{2}(?:[:.-]?\d{2})?z?)?/g, " ")
      .replace(/\bv?\d+(?:\.\d+)+\b/g, " ");
    const toks = s.split(SEP).filter((t) => t && !(
      /^v?\d+$/.test(t) ||
      (/^[0-9a-f]{7,12}$/.test(t) && /\d/.test(t)) ||
      /^\d{9,13}$/.test(t)
    ));
    return toks.join("-");
  }
  const PREFIX_MIN = 6;
  /* Token-boundary common prefix of raw lowercase stems, not counting the separator ("nullkey-" -> 7). */
  function sharedPrefix(a, b) {
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    if (i === a.length && i === b.length) return i;
    const cut = a.slice(0, i);
    const j = Math.max(cut.lastIndexOf("-"), cut.lastIndexOf("_"), cut.lastIndexOf("."), cut.lastIndexOf(" "));
    if (i < a.length && i < b.length && j < 0) return 0;
    const atBoundary = (i === a.length && SEP.test(b[i] || "")) || (i === b.length && SEP.test(a[i] || ""));
    return atBoundary ? i : j; // length of the shared prefix before its separator, e.g. 7 for "nullkey-"
  }
  function sameGroup(a, b) {
    if (extOf(a.name) !== extOf(b.name)) return false;
    const na = normBase(a.name), nb = normBase(b.name);
    if (na && na === nb) return true;
    return sharedPrefix(stemOf(a.name), stemOf(b.name)) >= PREFIX_MIN;
  }

  /* Map id -> {latest: bool, n, group} for files in groups of 2+. Newest by date added
     (ties: later created, then name). Independent of sort order. */
  function similarGroups(files) {
    const seen = new Set();
    const list = (files || []).filter((f) => f && f.id != null && !seen.has(f.id) && seen.add(f.id));
    const parent = list.map((_, i) => i);
    const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    for (let i = 0; i < list.length; i++)
      for (let j = i + 1; j < list.length; j++)
        if (find(i) !== find(j) && sameGroup(list[i], list[j])) parent[find(j)] = find(i);
    const groups = new Map();
    list.forEach((f, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(f); });
    const out = new Map();
    groups.forEach((g) => {
      if (g.length < 2) return;
      const newest = g.slice().sort((a, b) => addedTs(b) - addedTs(a) || createdTs(b) - createdTs(a) || byName(b, a))[0];
      const key = normBase(newest.name) || stemOf(newest.name);
      g.forEach((f) => out.set(f.id, { latest: f === newest, n: g.length, group: key + "." + extOf(f.name) }));
    });
    return out;
  }

  return { SORTS, DEFAULT, normSort, sortFiles, extOf, normBase, sharedPrefix, sameGroup, similarGroups, addedTs, createdTs };
});
