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

function fakePy(rel: string, content: string): ScannedFile {
  return {
    rel,
    abs: `/virtual/${rel}`,
    language: "python",
    isTest: false,
    isWorkflow: false,
    content,
    lines: content.split(/\r?\n/).length,
  };
}

test("Python state-machine scanner catches all 4 implicit state machine patterns (red) and passes frozen dataclass union (green)", () => {
  const badSoup = ["class Watchdog:", "    is_running: bool", "    is_armed: bool"].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakePy("src/watchdog.py", badSoup)).map((f) => f.rule),
    ["implicit-sm-boolean-soup"],
  );

  const badBag = [
    "class JobSnapshot:",
    "    status: str",
    "    error: str | None",
    "    finished_at: int | None",
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakePy("src/job.py", badBag)).map((f) => f.rule),
    ["implicit-sm-optional-bag"],
  );

  const badScattered = [
    "class Job:",
    "    def start(self):",
    '        self.status = "running"',
    "    def stop(self):",
    '        self.status = "stopped"',
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakePy("src/job_mut.py", badScattered)).map((f) => f.rule),
    ["implicit-sm-scattered-mutation"],
  );

  const badMatch = [
    "def label(state: OrderState) -> str:",
    "    match state:",
    "        case Pending():",
    '            return "pending"',
    "        case _:",
    '            return "unknown"',
  ].join("\n");
  assert.deepEqual(
    lintImplicitStateMachinesInFile(fakePy("src/label.py", badMatch)).map((f) => f.rule),
    ["implicit-sm-non-exhaustive-switch"],
  );

  const goodExplicit = [
    "class RunnerConfig:",
    "    mode: str",
    "    is_running: bool",
    "    is_armed: bool",
    "    endpoint: str | None",
    "    timeout_ms: int | None",
    "def label(state: OrderState) -> str:",
    "    match state:",
    "        case Pending():",
    '            return "pending"',
    "        case _:",
    "            assert_never(state)",
  ].join("\n");
  assert.deepEqual(lintImplicitStateMachinesInFile(fakePy("src/good.py", goodExplicit)), []);
});

test("Python no-comments allows SPDX, WARNING, SAFETY, and directives while rejecting prose comments", () => {
  const src = [
    "# SPDX-License-Identifier: MIT",
    "def inc(x: int) -> int:",
    "    # WARNING: caller enforces upper bound",
    "    # excuse comment",
    "    return x + 1",
  ].join("\n");
  const hits = lintNoComments("src/math_ops.py", src, "python");
  assert.deepEqual(
    hits.map((h) => h.line),
    [4],
  );
});

test("Python structure, prod zero-defect guards, and test-analyzer catch prod slop and test landmines", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-py-"));
  try {
    fs.writeFileSync(path.join(tmp, "pyproject.toml"), '[project]\nname = "demo"\n');
    fs.mkdirSync(path.join(tmp, "src"), { recursive: true });
    fs.mkdirSync(path.join(tmp, "tests"), { recursive: true });

    fs.writeFileSync(
      path.join(tmp, "src/service.py"),
      [
        "from typing import Any",
        "import time",
        "def reset_for_testing(payload: Any) -> int:",
        "    assert payload is not None",
        "    started = time.time()",
        "    elapsed = time.time() - started",
        "    try:",
        "        x = 1 # type: ignore",
        "    except Exception:",
        "        pass",
        "    return int(elapsed)",
      ].join("\n"),
    );

    fs.writeFileSync(
      path.join(tmp, "tests/test_bad.py"),
      [
        "import datetime",
        "import os",
        "import random",
        "import time",
        "import pytest",
        "@pytest.mark.skip",
        "def test_smells():",
        "    time.sleep(0.1)",
        '    os.environ["MODE"] = "1"',
        "    _ = datetime.datetime.now()",
        "    _ = random.random()",
        "    start = time.monotonic()",
        "    assert time.monotonic() - start < 0.5",
        "    assert True",
        "    assert calc(2) == calc(2)",
        "    assert status_code in (200, 404)",
        "def calc(x):",
        "    return x + 1",
      ].join("\n"),
    );

    const report = scanRepo(tmp);
    const rules = new Set(report.findings.map((f) => f.rule));
    assert.ok(rules.has("no-test-only-production-seam"));
    assert.ok(rules.has("no-chained-or-any-cast"));
    assert.ok(rules.has("no-swallowing-catch"));
    assert.ok(rules.has("suppression-audit"));
    assert.ok(rules.has("no-release-stripped-assert"));
    assert.ok(rules.has("cdc-wall-clock-duration"));
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

test("diff-cheats catches newly added Python @pytest.mark.skip, bare # noqa, and pytest || true", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-py-diff-"));
  try {
    spawnSync("git", ["init", "-q"], { cwd: tmp });
    spawnSync("git", ["config", "user.email", "ci@test.local"], { cwd: tmp });
    spawnSync("git", ["config", "user.name", "CI"], { cwd: tmp });
    fs.writeFileSync(path.join(tmp, "test_app.py"), "def test_ok():\n    assert 1 + 1 == 2\n");
    fs.writeFileSync(path.join(tmp, "ci.sh"), "pytest\n");
    spawnSync("git", ["add", "."], { cwd: tmp });
    spawnSync("git", ["commit", "-q", "-m", "init"], { cwd: tmp });

    fs.writeFileSync(
      path.join(tmp, "test_app.py"),
      "@pytest.mark.skip\ndef test_ok():\n    x = 1 # noqa\n",
    );
    fs.writeFileSync(path.join(tmp, "ci.sh"), "pytest || true\n");

    const hits = scanGitDiffCheats(tmp, "HEAD");
    const rules = new Set(hits.map((h) => h.rule));
    assert.ok(rules.has("diff-python-skipped-test"));
    assert.ok(rules.has("diff-python-bare-suppression"));
    assert.ok(rules.has("diff-swallowed-failure"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("System 1 classifier extracts Python SUT imports on templates/python-reference", () => {
  const pyRef = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "templates", "python-reference");
  const report = buildSystem1Packet(pyRef, { maxCandidates: 10 });
  assert.ok(report.candidates.length >= 3);
  const tableCand = report.candidates.find((c) => c.file.endsWith("test_transition_table.py"));
  assert.ok(tableCand);
  assert.equal(tableCand.hasSutImport, true);
});
