import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanGitDiffCheats } from "../../src/ci-auditor.ts";
import type { ScannedFile } from "../../src/discover.ts";
import { scanRepo } from "../../src/ladder.ts";
import { lintImplicitStateMachinesInFile } from "../../src/state-machines/index.ts";
import { analyzeCveAndPostmortemGuards } from "../../src/zero-defect/cve-and-agent-guards.ts";

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
