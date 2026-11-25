import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { discoverRepo, isTestFilePath } from "../../src/discover.ts";
import { analyzeProdZeroDefectRules } from "../../src/prod-guards.ts";
import { analyzeStateMachines } from "../../src/state-machines/index.ts";
import { analyzeTests } from "../../src/test-analyzer.ts";
import { analyzePerfHygiene } from "../../src/zero-defect/perf-lints.ts";

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cal-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content, "utf8");
    }
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("perf-lints ignores Rust impl-for blocks and JS comment prose while catching real loops", () => {
  withTempRepo(
    {
      "src/repo.rs": [
        "pub struct Repo;",
        "pub trait Store { fn load(&self); }",
        "impl Store for Repo {",
        "  fn load(&self) { let _ = sqlx::query!(\"SELECT 1\").fetch_one(db); }",
        "}",
        "pub fn batch(ids: &[u64]) {",
        "  for id in ids {",
        "    let _ = sqlx::query!(\"SELECT 1\").fetch_one(db);",
        "  }",
        "}",
      ].join("\n"),
      "src/parser.js": [
        "// helper for parsing tokens",
        "export function parse(items) {",
        "  const first = items.find((x) => x.ok);",
        "  return first;",
        "}",
      ].join("\n"),
    },
    (dir) => {
      const findings = analyzePerfHygiene(discoverRepo(dir));
      const rustHits = findings.filter((f) => f.file === "src/repo.rs");
      assert.equal(rustHits.length, 1);
      assert.equal(rustHits[0]?.rule, "perf-nplus1-io-in-loop");
      assert.equal(rustHits[0]?.line, 8);

      const jsHits = findings.filter((f) => f.file === "src/parser.js");
      assert.equal(jsHits.length, 0);
    },
  );
});

test("Rust wildcard match check ignores &str literal matches and flags enum wildcard matches once per line", () => {
  withTempRepo(
    {
      "src/labels.rs": [
        "pub fn label(status: &str) -> &'static str {",
        '  match status { "active" => "Active", _ => "Other" }',
        "}",
        "pub enum OrderState { Pending, Shipped, Cancelled }",
        "pub fn code(state: OrderState) -> u8 {",
        "  match state { OrderState::Pending => 1, _ => 0 }",
        "}",
      ].join("\n"),
    },
    (dir) => {
      const findings = analyzeStateMachines(discoverRepo(dir));
      assert.equal(findings.length, 1);
      assert.equal(findings[0]?.rule, "implicit-sm-non-exhaustive-switch");
      assert.equal(findings[0]?.line, 6);
    },
  );
});

test("coverage-policy tooling tests are not flagged as coverage-farm files while real farm files are", () => {
  withTempRepo(
    {
      "tools/check-coverage-policy.test.ts": 'import { ok } from "../../src/a.ts"; test("p", () => expect(ok()).toBe(true));\n',
      "tools/coverage-inventory.test.ts": 'import { ok } from "../../src/a.ts"; test("i", () => expect(ok()).toBe(true));\n',
      "tests/coverage-extra.test.ts": 'import { ok } from "../../src/a.ts"; test("e", () => expect(ok()).toBe(true));\n',
      "src/a.ts": "export const ok = () => true;\n",
    },
    (dir) => {
      const { findings } = analyzeTests(discoverRepo(dir));
      const farmHits = findings.filter((f) => f.rule === "no-coverage-farm-file");
      assert.equal(farmHits.length, 1);
      assert.equal(farmHits[0]?.file, "tests/coverage-extra.test.ts");
    },
  );
});

test("discovery recognizes hyphenated Python tests, skips minified bundles & archived docs, and respects deadlines", () => {
  assert.equal(isTestFilePath("scripts/test-db-move.py"), true);
  assert.equal(isTestFilePath("scripts/run-tests.py"), true);

  const minifiedLine = `var R=(()=>{${"let a=1;".repeat(400)}return 1})();`;
  withTempRepo(
    {
      "src/vendor/runtime.js": `${minifiedLine}\n`,
      "docs/research/deep/data/round-1/source/app.py": "assert 1 == 1\n",
      "scripts/test-db-move.py": "assert True\n",
      "src/poller.py": [
        "import time",
        "def poll():",
        "    deadline = time.monotonic() + 30",
        "    while True:",
        "        if time.monotonic() > deadline:",
        "            break",
      ].join("\n"),
    },
    (dir) => {
      const repo = discoverRepo(dir);
      assert.equal(repo.files.some((f) => f.rel === "src/vendor/runtime.js"), false);
      assert.equal(repo.files.some((f) => f.rel.startsWith("docs/research/")), false);
      const zd = analyzeProdZeroDefectRules(repo);
      assert.equal(zd.length, 0);
    },
  );
});
