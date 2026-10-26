// Run: node tests/js/fm_sort_test.js  (driven by tests/test_fm_sort.py)
"use strict";
const assert = require("assert");
const S = require("../../static/fm-sort.js");
let n = 0;
const t = (name, fn) => { fn(); n++; };
const iso = (d) => new Date(Date.UTC(2026, 9, d, 12)).toISOString();
const F = (id, name, added, created) => ({ id, name, added_at: added && iso(added), created_at: created && iso(created), updated_at: iso(28) });
const names = (l) => l.map((f) => f.name);

const files = [
  F("1", "b.TXT", 3, 1), F("2", "a.apk", 1, 5), F("3", "Zeta.md", 2, 2), F("4", "noext", 5, 3), F("5", "c.apk", 4, 4), F("6", "a10.txt", 6, 6), F("7", "a9.txt", 7, 7),
];
t("default is name A-Z, case-insensitive, numeric-aware", () => {
  assert.deepStrictEqual(S.normSort(null), { key: "name", dir: "asc" });
  assert.deepStrictEqual(names(S.sortFiles(files)), ["a.apk", "a9.txt", "a10.txt", "b.TXT", "c.apk", "noext", "Zeta.md"]);
  assert.deepStrictEqual(names(S.sortFiles(files, { key: "name", dir: "desc" })), ["Zeta.md", "noext", "c.apk", "b.TXT", "a10.txt", "a9.txt", "a.apk"]);
});
t("ext groups by extension then name; no-extension last; desc flips groups only", () => {
  assert.deepStrictEqual(names(S.sortFiles(files, { key: "ext", dir: "asc" })), ["a.apk", "c.apk", "Zeta.md", "a9.txt", "a10.txt", "b.TXT", "noext"]);
  assert.deepStrictEqual(names(S.sortFiles(files, { key: "ext", dir: "desc" })), ["a9.txt", "a10.txt", "b.TXT", "Zeta.md", "a.apk", "c.apk", "noext"]);
  assert.strictEqual(S.extOf("x.tar.GZ"), "gz"); assert.strictEqual(S.extOf(".bashrc"), ""); assert.strictEqual(S.extOf("dir/a.b/c"), "");
});
t("date added / created asc+desc, fallbacks", () => {
  assert.deepStrictEqual(names(S.sortFiles(files, { key: "added", dir: "asc" })), ["a.apk", "Zeta.md", "b.TXT", "c.apk", "noext", "a10.txt", "a9.txt"]);
  assert.deepStrictEqual(names(S.sortFiles(files, { key: "added", dir: "desc" })), ["a9.txt", "a10.txt", "noext", "c.apk", "b.TXT", "Zeta.md", "a.apk"]);
  assert.deepStrictEqual(names(S.sortFiles(files, { key: "created", dir: "asc" })), ["b.TXT", "Zeta.md", "noext", "c.apk", "a.apk", "a10.txt", "a9.txt"]);
  // missing created -> added; missing added -> updated_at
  const fb = [{ id: "x", name: "x", updated_at: iso(10) }, { id: "y", name: "y", added_at: iso(9) }, { id: "z", name: "z", added_at: iso(11), created_at: iso(1) }];
  assert.deepStrictEqual(names(S.sortFiles(fb, { key: "created", dir: "asc" })), ["z", "y", "x"]);
  assert.deepStrictEqual(names(S.sortFiles(fb, { key: "added", dir: "asc" })), ["y", "x", "z"]);
  // ties fall back to name A-Z; does not mutate input
  const tie = [F("a", "b", 1), F("b", "a", 1)];
  assert.deepStrictEqual(names(S.sortFiles(tie, { key: "added", dir: "desc" })), ["a", "b"]);
  assert.deepStrictEqual(names(tie), ["b", "a"]);
  assert.deepStrictEqual(S.normSort({ key: "bogus", dir: "sideways" }), { key: "name", dir: "asc" });
});

// ---- similar names / Latest ----
const NK = [
  ["k1", "nullkey-chording-test-96e43b4.apk", 1],
  ["k2", "nullkey-layouts-test-7cdf34e.apk", 2],
  ["k3", "nullkey-rewrite-v2-e45970d-release.apk", 3],
  ["k4", "nullkey-terminal-test-900c196.apk", 6],
  ["i1", "nullkey-chording-test-96e43b4-build-info.txt", 1],
  ["i2", "nullkey-layouts-test-7cdf34e-build-info.txt", 2],
  ["i4", "nullkey-terminal-test-900c196-build-info.txt", 7],
  ["a1", "nullkey-rewrite-v2-e45970d-release.aab", 3],
  ["r1", "README.txt", 9],
  ["m1", "morc-smoke.txt", 10],
].map(([id, name, d]) => F(id, name, d));
t("NullKey APKs group together; newest by date added is Latest", () => {
  const g = S.similarGroups(NK);
  for (const id of ["k1", "k2", "k3", "k4"]) assert.strictEqual(g.get(id).n, 4, id);
  assert.strictEqual(g.get("k4").latest, true);
  assert.deepStrictEqual(["k1", "k2", "k3"].map((id) => g.get(id).latest), [false, false, false]);
});
t("build-info .txt files group separately from the .apk files", () => {
  const g = S.similarGroups(NK);
  for (const id of ["i1", "i2", "i4"]) assert.strictEqual(g.get(id).n, 3, id);
  assert.notStrictEqual(g.get("i1").group, g.get("k1").group);
  assert.strictEqual(g.get("i4").latest, true);
  assert.strictEqual(g.get("k4").latest, true);
  assert.strictEqual(g.has("a1"), false, "single .aab is not grouped with .apk");
  assert.strictEqual(g.has("r1"), false); assert.strictEqual(g.has("m1"), false);
});
t("grouping is independent of sort order and input order", () => {
  const a = S.similarGroups(S.sortFiles(NK, { key: "ext", dir: "desc" }));
  const b = S.similarGroups(NK.slice().reverse());
  for (const f of NK) assert.deepStrictEqual(a.get(f.id), b.get(f.id));
});
t("normalisation: hashes, versions, dates, timestamps, copy suffixes", () => {
  assert.strictEqual(S.normBase("nullkey-terminal-test-900c196.apk"), "nullkey-terminal-test");
  assert.strictEqual(S.normBase("App v1.2.3.apk"), "app");
  assert.strictEqual(S.normBase("App-1.4.apk"), "app");
  assert.strictEqual(S.normBase("report (1).pdf"), "report");
  assert.strictEqual(S.normBase("report-copy.pdf"), "report");
  assert.strictEqual(S.normBase("Report Copy 2.pdf"), "report");
  assert.strictEqual(S.normBase("backup-2026-10-26.tgz"), "backup");
  assert.strictEqual(S.normBase("backup-20261026T172142Z.tgz"), "backup");
  assert.strictEqual(S.normBase("log_1761500000.txt"), "log");
  assert.strictEqual(S.normBase("deadbeefcafe.txt"), "deadbeefcafe", "all-letter hex word kept");
  const g = S.similarGroups([F("a", "report.pdf", 1), F("b", "report (1).pdf", 3), F("c", "Report-copy.pdf", 2), F("d", "report.docx", 4)]);
  assert.strictEqual(g.get("a").n, 3); assert.strictEqual(g.get("b").latest, true); assert.strictEqual(g.has("d"), false);
});
t("shared long prefix at a separator groups; short or mid-word prefixes don't", () => {
  assert.ok(S.sameGroup({ name: "nullkey-alpha.apk" }, { name: "nullkey-beta.apk" }));
  assert.ok(!S.sameGroup({ name: "notes-a.md" }, { name: "notes-b.md" }), "5-char prefix too short");
  assert.ok(!S.sameGroup({ name: "projectile.txt" }, { name: "projection.txt" }), "mid-word prefix");
  assert.ok(!S.sameGroup({ name: "nullkey-alpha.apk" }, { name: "nullkey-alpha.txt" }), "extension must match");
  assert.ok(!S.sameGroup({ name: "a.txt" }, { name: "b.txt" }));
});
t("duplicates (search name+content hits) count once; singletons unmarked", () => {
  const x = F("x", "nullkey-a-1234567.apk", 1), y = F("y", "nullkey-a-89abcde.apk", 2);
  const g = S.similarGroups([x, y, Object.assign({}, y)]);
  assert.strictEqual(g.get("x").n, 2); assert.strictEqual(g.get("y").latest, true);
  assert.strictEqual(S.similarGroups([x]).size, 0);
});
console.log(`OK ${n}`);
