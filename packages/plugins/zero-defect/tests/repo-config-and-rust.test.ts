import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { analyzeWave5AiFirstGuards } from "@veristack/plugin-lang-typescript";
import { analyzeWave6TitansAGuards } from "@veristack/plugin-lang-typescript";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import type { ScannedFile } from "@veristack/core";
import { scanRepo } from "@veristack/core";
import { lintImplicitStateMachinesInFile } from "@veristack/plugin-state-machines";
import { analyzeCveAndPostmortemGuards } from "@veristack/plugin-zero-defect";
import { analyzeOssGuards } from "@veristack/plugin-zero-defect";
import { analyzeRuntimeGuards } from "@veristack/plugin-zero-defect";

function fakeFile(rel: string, content: string, language?: ScannedFile["language"]): ScannedFile {
  return {
    rel,
    abs: `/virtual/${rel}`,
    language,
    isTest: false,
    isWorkflow: false,
    content,
    lines: content.split(/\r?\n/).length,
  };
}

test(".vstack.json and --disable turn off selected rules, override severities, and ignore paths", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cfg-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "spikes"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "Cargo.toml"), '[package]\nname = "demo"\nversion = "0.1.0"\n');
    const longBody = Array.from({ length: 520 }, (_, i) => `pub fn f_${i}(x: i32) -> i32 { x + ${i} }`).join("\n");
    fs.writeFileSync(
      path.join(tmp, "src/lib.rs"),
      `// prose comment rejected by team ADR\n${longBody}\npub fn panic_site(v: Option<i32>) -> i32 { v.unwrap() }\n`,
    );
    fs.writeFileSync(path.join(tmp, "spikes/exp.rs"), "pub fn spike(v: Option<i32>) -> i32 { v.unwrap() }\n");

    const raw = scanRepo(tmp);
    assert.ok(raw.findings.some((f) => f.rule === "no-comments"));
    assert.ok(raw.findings.some((f) => f.rule === "max-file-lines"));
    assert.ok(raw.findings.some((f) => f.rule === "rust-prod-unwrap-or-expect" && f.severity === "error"));
    assert.ok(raw.findings.some((f) => f.file === "spikes/exp.rs"));

    fs.writeFileSync(
      path.join(tmp, ".vstack.json"),
      JSON.stringify(
        {
          rules: {
            "no-comments": "off",
            "max-file-lines": "off",
            "long-file": "off",
            "rust-prod-unwrap-or-expect": "warn",
          },
          ignore: ["spikes/**"],
        },
        null,
        2,
      ),
    );

    const configured = scanRepo(tmp);
    assert.equal(configured.summary.noCommentCount, 0);
    assert.ok(!configured.findings.some((f) => f.rule === "max-file-lines"));
    assert.ok(!configured.findings.some((f) => f.file === "spikes/exp.rs"));
    const unwrapHit = configured.findings.find((f) => f.rule === "rust-prod-unwrap-or-expect");
    assert.ok(unwrapHit);
    assert.equal(unwrapHit.severity, "warn");
    assert.equal(configured.config?.path, ".vstack.json");
    assert.ok(configured.config?.disabledRules.includes("no-comments"));

    const cliDisabled = scanRepo(tmp, { disableRules: ["rust-prod-unwrap-or-expect"] });
    assert.ok(!cliDisabled.findings.some((f) => f.rule === "rust-prod-unwrap-or-expect"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("diff-cheats flags stealth disabling of rules inside .vstack.json", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-cfg-diff-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    fs.writeFileSync(path.join(tmp, ".vstack.json"), '{"rules": {}}\n');
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(path.join(tmp, ".vstack.json"), '{"rules": {"no-swallowing-catch": "off"}}\n');
    const hits = scanGitDiffCheats(tmp, "HEAD");
    assert.ok(hits.some((h) => h.rule === "diff-config-strictness-downgrade"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("Rust src/tests.rs is treated as a test module and wire/row DTO structs skip implicit-sm-optional-bag", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rs-cal-"));
  try {
    fs.writeFileSync(path.join(tmp, "Cargo.toml"), '[package]\nname = "demo"\nversion = "0.1.0"\n');
    fs.mkdirSync(path.join(tmp, "src/feature"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "tests/support"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "src/feature/tests.rs"),
      "#[test]\nfn checks_value() {\n    let x: Option<i32> = Some(1);\n    assert_eq!(x.expect(\"present\"), 1);\n}\n",
    );
    fs.writeFileSync(
      path.join(tmp, "tests/support/harness.rs"),
      "pub fn setup() -> i32 { Some(1).unwrap() }\n",
    );

    const report = scanRepo(tmp);
    assert.ok(!report.findings.some((f) => f.rule === "rust-prod-unwrap-or-expect"));
    assert.equal(report.summary.testFiles, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  const serdeAndRow = [
    "#[derive(Debug, Deserialize)]",
    "pub struct StripeCheckoutSession {",
    "    pub status: String,",
    "    pub url: Option<String>,",
    "    pub subscription: Option<String>,",
    "}",
    "pub struct JobRow {",
    "    pub status: String,",
    "    pub error: Option<String>,",
    "    pub finished_at: Option<i64>,",
    "}",
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeFile("src/wire.rs", serdeAndRow, "rust")), []);

  const domainBag = [
    "pub struct PaymentBag {",
    "    pub status: PaymentStatus,",
    "    pub auth_code: Option<String>,",
    "    pub failure_reason: Option<String>,",
    "}",
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeFile("src/domain.rs", domainBag, "rust")).map((f) => f.rule),
    ["implicit-sm-optional-bag"],
  );
});

test("db-migration-missing-lock-timeout skips SQLite and same-file CREATE TABLE indexes while catching Postgres locking DDL", () => {
  const sqliteMig = fakeFile(
    "crates/app/migrations/sqlite/001_init.sql",
    "CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);\nCREATE INDEX idx_items_name ON items (name);\nALTER TABLE items ADD COLUMN extra TEXT;\n",
  );
  assert.deepEqual(analyzeCveAndPostmortemGuards(sqliteMig), []);

  const pgFreshTable = fakeFile(
    "crates/app/migrations/postgres/001_init.sql",
    "CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL);\nCREATE INDEX idx_orders_user ON orders (user_id);\n",
  );
  assert.deepEqual(analyzeCveAndPostmortemGuards(pgFreshTable), []);

  const pgExistingTableLock = fakeFile(
    "crates/app/migrations/postgres/002_idx.sql",
    "CREATE INDEX idx_orders_created ON orders (created_at);\n",
  );
  assert.deepEqual(
    analyzeCveAndPostmortemGuards(pgExistingTableLock).map((f) => f.rule),
    ["db-migration-missing-lock-timeout"],
  );
});

test("field-triage FP fixes: serde per-struct scope, sync commit(), constant RegExp, Workers body.cancel(), and prior backslash guard", () => {
  const separateSerdeStructs = fakeFile(
    "src/wire.rs",
    [
      "#[derive(Deserialize)]",
      "#[serde(deny_unknown_fields)]",
      "pub struct StrictHeader { pub name: String }",
      "#[derive(Deserialize)]",
      "pub struct OpenEnvelope { #[serde(flatten)] pub extra: Map<String, Value> }",
    ].join("\n"),
    "rust",
  );
  assert.deepEqual(analyzeOssGuards(separateSerdeStructs).filter((f) => f.rule === "serde-deny-unknown-with-flatten"), []);

  const sameSerdeStruct = fakeFile(
    "src/bad.rs",
    [
      "#[derive(Deserialize)]",
      "#[serde(deny_unknown_fields)]",
      "pub struct Broken { #[serde(flatten)] pub extra: Map<String, Value> }",
    ].join("\n"),
    "rust",
  );
  assert.ok(analyzeOssGuards(sameSerdeStruct).some((f) => f.rule === "serde-deny-unknown-with-flatten"));

  const syncCommitJs = fakeFile(
    "assets/canvas.js",
    [
      "function commit(next, label) { history.push({ next, label }); }",
      "function addNode(n) { commit(n, 'added'); }",
    ].join("\n"),
    "javascript",
  );
  assert.deepEqual(analyzeRuntimeGuards(syncCommitJs).filter((f) => f.rule === "no-floating-side-effect-promise"), []);

  const constRegexTs = fakeFile(
    "src/router.ts",
    'const uuid = "[a-f0-9]{8}";\nexport const route = new RegExp(`^/v1/(${uuid})$`);\n',
    "typescript",
  );
  assert.deepEqual(analyzeOssGuards(constRegexTs).filter((f) => f.rule === "regex-empty-alternation-or-unescaped"), []);

  const workerCancelTs = fakeFile(
    "workers/edge/src/index.ts",
    "export default { async fetch(req: Request): Promise<Response> { const response = await fetch(req); await response.body?.cancel(); return new Response(null); } };\n",
    "typescript",
  );
  assert.deepEqual(analyzeWave5AiFirstGuards(workerCancelTs).filter((f) => f.rule === "mcp-body-cancel-hang"), []);

  const priorBackslashTs = fakeFile(
    "src/routing.ts",
    [
      "export function parseTarget(raw: string): boolean {",
      "  if (/[^\\x21-\\x7e]|\\\\/.test(raw)) return false;",
      '  return raw.startsWith("/") && !raw.startsWith("//");',
      "}",
    ].join("\n"),
    "typescript",
  );
  assert.deepEqual(
    analyzeWave6TitansAGuards(priorBackslashTs).filter((f) => f.rule === "url-slash-check-missing-backslash"),
    [],
  );
});
