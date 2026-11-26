import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");
const maxLinesScript = path.join(repoRoot, "scripts", "check-max-lines.mjs");

test("vstack scan --json returns schemaVersion 1 and zero prose comments", () => {
  const res = spawnSync(process.execPath, [binPath, "scan", repoRoot, "--json", "--fail-on-cheats", "--allow-missing-rungs"], {
    encoding: "utf8",
  });
  assert.equal(res.status, 0, res.stderr);
  const parsed = JSON.parse(res.stdout);
  assert.equal(parsed.schemaVersion, 1);
  assert.equal(parsed.rungs.length, 9);
  assert.equal(parsed.summary.noCommentCount, 0);
});

test("vstack no-comments --fail exits 0 on verification-stack itself", () => {
  const res = spawnSync(process.execPath, [binPath, "no-comments", repoRoot, "--fail"], {
    encoding: "utf8",
  });
  assert.equal(res.status, 0, res.stdout + res.stderr);
});

test("vstack classify --json emits versioned System 1 improvement packet", () => {
  const res = spawnSync(process.execPath, [binPath, "classify", repoRoot, "--json", "--max", "10"], {
    encoding: "utf8",
  });
  assert.equal(res.status, 0, res.stderr);
  const parsed = JSON.parse(res.stdout);
  assert.equal(parsed.schemaVersion, 1);
  assert.equal(parsed.rubricVersion, "system1-improvements-v1");
  assert.ok(parsed.requests.length > 0);
});

test("vstack state-machines --fail exits 0 on verification-stack itself", () => {
  const res = spawnSync(process.execPath, [binPath, "state-machines", repoRoot, "--fail"], {
    encoding: "utf8",
  });
  assert.equal(res.status, 0, res.stdout + res.stderr);
});

test("vstack scan --strict rejects ratchets, disabled rules, missing receipts, and any finding", () => {
  const ratchetRejected = spawnSync(
    process.execPath,
    [binPath, "scan", repoRoot, "--strict", "--ratchet", "/tmp/unused-ratchet.json"],
    { encoding: "utf8" },
  );
  assert.equal(ratchetRejected.status, 1);
  assert.match(ratchetRejected.stderr, /forbids --ratchet/);

  const disableRejected = spawnSync(
    process.execPath,
    [binPath, "scan", repoRoot, "--strict", "--disable", "no-comments"],
    { encoding: "utf8" },
  );
  assert.equal(disableRejected.status, 1);
  assert.match(disableRejected.stderr, /forbids --config and --disable/);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-strict-fail-"));
  try {
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "src", "warn.ts"), "export function f() { try { return 1; } catch {} }\n");
    const failed = spawnSync(process.execPath, [binPath, "scan", tmp, "--strict"], { encoding: "utf8" });
    assert.equal(failed.status, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check-max-lines enforces 500-line ceiling on verification-stack and fails on 501-line file", () => {
  const ok = spawnSync(process.execPath, [maxLinesScript, "--dir", repoRoot], { encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-maxlines-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    fs.writeFileSync(path.join(tmp, "big.ts"), `${Array.from({ length: 501 }, (_, i) => `export const a${i} = ${i};`).join("\n")}\n`);
    spawnSync("git", ["add", "big.ts"], { cwd: tmp });
    const bad = spawnSync(process.execPath, [maxLinesScript, "--dir", tmp], { encoding: "utf8" });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /big\.ts: 502 lines|big\.ts: 501 lines/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
