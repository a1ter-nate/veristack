import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanGitDiffCheats } from "@veristack/plugin-ci-auditor";
import type { ScannedFile } from "@veristack/core";
import { scanRepo } from "@veristack/core";
import { lintNoComments } from "@veristack/plugin-anti-slop";
import { lintImplicitStateMachinesInFile } from "@veristack/plugin-state-machines";
import { buildSystem1Packet } from "@veristack/plugin-circuits";

function fakeRs(rel: string, content: string): ScannedFile {
  return {
    rel,
    abs: `/virtual/${rel}`,
    language: "rust",
    isTest: false,
    isWorkflow: false,
    content,
    lines: content.split(/\r?\n/).length,
  };
}

test("Rust state-machine scanner catches all 4 implicit state machine patterns (red) and passes explicit enum (green)", () => {
  const badSoup = `pub struct Watchdog { pub is_running: bool, pub is_armed: bool }`;
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeRs("src/watchdog.rs", badSoup)).map((f) => f.rule),
    ["implicit-sm-boolean-soup"],
  );

  const badBag = [
    "pub struct JobSnapshot {",
    "    pub status: JobStatus,",
    "    pub error: Option<String>,",
    "    pub finished_at: Option<u64>,",
    "}",
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeRs("src/job.rs", badBag)).map((f) => f.rule),
    ["implicit-sm-optional-bag"],
  );

  const badScattered = [
    "impl Job {",
    "    pub fn start(&mut self) { self.status = JobStatus::Running; }",
    "    pub fn stop(&mut self) { self.status = JobStatus::Stopped; }",
    "}",
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeRs("src/job_mut.rs", badScattered)).map((f) => f.rule),
    ["implicit-sm-scattered-mutation"],
  );

  const badWildcard = [
    "pub fn label(state: OrderState) -> &'static str {",
    "    match state {",
    '        OrderState::Pending => "pending",',
    '        _ => "unknown",',
    "    }",
    "}",
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakeRs("src/label.rs", badWildcard)).map((f) => f.rule),
    ["implicit-sm-non-exhaustive-switch"],
  );

  const goodExplicit = [
    "pub enum OrderState { Pending { amount: u32 }, Shipped { tracking: String } }",
    "pub struct RunnerConfig { pub mode: Mode, pub enable_cache: bool, pub verbose: bool, pub endpoint: Option<String>, pub timeout_ms: Option<u64> }",
    "pub fn label(state: &OrderState) -> &'static str {",
    "    match state {",
    '        OrderState::Pending { .. } => "pending",',
    '        OrderState::Shipped { .. } => "shipped",',
    "    }",
    "}",
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakeRs("src/good.rs", goodExplicit)), []);
});

test("Rust no-comments allows pub rustdoc, module docs, and SAFETY/WARNING while rejecting prose and private rustdoc", () => {
  const src = [
    "//! Module documentation.",
    "// SPDX-License-Identifier: MIT",
    "/// Public contract doc.",
    "pub fn inc(x: i32) -> i32 {",
    "    // WARNING: wrapping arithmetic is intentional",
    "    x.wrapping_add(1)",
    "}",
    "/// Private rustdoc should fail.",
    "fn helper() -> i32 {",
    "    // excuse comment",
    "    1",
    "}",
  ].join("\n");
  const hits = lintNoComments("src/lib.rs", src, "rust");
  assert.deepEqual(
    hits.map((h) => h.line),
    [8, 10],
  );
});

test("Rust structure and test-analyzer catch prod slop and test landmines", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rs-"));
  try {
    fs.writeFileSync(path.join(tmp, "Cargo.toml"), '[package]\nname = "demo"\nversion = "0.1.0"\n');
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "tests"), { recursive: true });

    fs.writeFileSync(
      path.join(tmp, "src/lib.rs"),
      [
        "#[allow(clippy::all)]",
        "pub fn reset_for_testing(input: Option<i32>) -> i32 {",
        "    let val = input.unwrap();",
        "    if let Err(_) = std::fs::read_to_string(\"x\") {}",
        "    unsafe { std::mem::transmute::<i32, i32>(val) }",
        "}",
      ].join("\n"),
    );

    fs.writeFileSync(
      path.join(tmp, "tests/bad_test.rs"),
      [
        "use std::time::{Duration, Instant, SystemTime};",
        "#[test]",
        "#[ignore]",
        "fn smells() {",
        "    std::thread::sleep(Duration::from_millis(10));",
        '    unsafe { std::env::set_var("MODE", "1"); }',
        "    let _now = SystemTime::now();",
        "    let _r: u32 = rand::random();",
        "    let start = Instant::now();",
        "    assert!(start.elapsed().as_millis() < 50);",
        "    assert!(true);",
        "    assert_eq!(calc(2), calc(2));",
        "    assert!([200, 404].contains(&200));",
        "}",
        "fn calc(x: i32) -> i32 { x + 1 }",
      ].join("\n"),
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    const ids = report.findings.map((f) => f.id);
    assert.ok(rules.has("suppression-audit"));
    assert.ok(rules.has("no-test-only-production-seam"));
    assert.ok(ids.some((id) => id.startsWith("AS:rs-unwrap:")));
    assert.ok(ids.some((id) => id.startsWith("AS:rs-unsafe:")));
    assert.ok(rules.has("no-swallowing-catch"));
    assert.ok(rules.has("rust-unjustified-unsafe"));
    assert.ok(rules.has("rust-prod-unwrap-or-expect"));
    assert.ok(rules.has("no-unexercised-test"));
    assert.ok(rules.has("no-fixed-sleep"));
    assert.ok(rules.has("test-discipline"));
    assert.ok(rules.has("no-imported-mutation"));
    assert.ok(rules.has("no-test-nondeterminism"));
    assert.ok(rules.has("no-elapsed-time-bound"));
    assert.ok(rules.has("weak-asserts-tautology"));
    assert.ok(rules.has("self-derived-expectation"));
    assert.ok(rules.has("no-multi-status-assertion"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("diff-cheats catches newly added Rust #[ignore], blanket #[allow], and cargo test || true", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rs-diff-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    fs.writeFileSync(path.join(tmp, "lib.rs"), "pub fn ok() -> i32 { 1 }\n");
    fs.writeFileSync(path.join(tmp, "ci.sh"), "cargo test\n");
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(
      path.join(tmp, "lib.rs"),
      "#[allow(warnings)]\n#[test]\n#[ignore]\nfn skipped() {}\n",
    );
    fs.writeFileSync(path.join(tmp, "ci.sh"), "cargo test || true\n");

    const hits = scanGitDiffCheats(tmp, "HEAD");
    const rules = new Set(hits.map((h) => h.rule));
    assert.ok(rules.has("diff-rust-allow-lint"));
    assert.ok(rules.has("diff-rust-ignored-test"));
    assert.ok(rules.has("diff-swallowed-failure"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("System 1 classifier extracts Rust SUT imports and classifies templates/rust-reference as BEHAVIOR", () => {
  const rustRef = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "templates", "rust-reference");
  const report = buildSystem1Packet(rustRef, { maxCandidates: 10 });
  assert.ok(report.candidates.length >= 2);
  const tableCand = report.candidates.find((c) => c.file.endsWith("transition_table.rs"));
  assert.ok(tableCand);
  assert.equal(tableCand.hasSutImport, true);
  const mbtCand = report.candidates.find((c) => c.file.endsWith("property_and_mbt.rs"));
  assert.ok(mbtCand);
  assert.equal(mbtCand.hasSutImport, true);
});
