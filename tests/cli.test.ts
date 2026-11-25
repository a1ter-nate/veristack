import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const binPath = path.join(repoRoot, "bin", "vstack.mjs");

test("vstack scan --json returns schemaVersion 1 and exits 0 on clean repo", () => {
  const res = spawnSync(process.execPath, [binPath, "scan", repoRoot, "--json", "--fail-on-cheats"], {
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
