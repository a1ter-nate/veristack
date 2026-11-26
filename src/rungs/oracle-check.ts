import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface TwoSidedOracleResult {
  passed: boolean;
  baseRef: string;
  baseTestsOnHeadCodeExit: number;
  headTestsOnHeadCodeExit: number;
  declaredBehaviorChange: boolean;
  reason: string;
}

export function runTwoSidedOracleCheck(
  repoPath: string,
  baseRef: string,
  testCmd: string,
): TwoSidedOracleResult {
  if (!baseRef || baseRef.startsWith("-")) {
    throw new Error(`Invalid git baseRef "${baseRef}".`);
  }
  const root = path.resolve(repoPath);
  const headRun = spawnSync(testCmd, [], { cwd: root, shell: true, encoding: "utf8", timeout: 120_000 });
  const headExit = headRun.status ?? 1;
  if (headExit !== 0) {
    return {
      passed: false,
      baseRef,
      baseTestsOnHeadCodeExit: -1,
      headTestsOnHeadCodeExit: headExit,
      declaredBehaviorChange: false,
      reason: `Head test suite fails (exit ${headExit}).`,
    };
  }

  const diffFiles = spawnSync("git", ["diff", "--name-only", baseRef, "--"], { cwd: root, encoding: "utf8" });
  const testPattern = /(?:^|\/)(?:tests?|__tests__|spec)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.(?:py|rs|go)$|Tests?\.cs$/i;
  const changedTestFiles = (diffFiles.stdout ?? "")
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && testPattern.test(s));

  if (changedTestFiles.length === 0) {
    return {
      passed: true,
      baseRef,
      baseTestsOnHeadCodeExit: 0,
      headTestsOnHeadCodeExit: 0,
      declaredBehaviorChange: false,
      reason: "No existing test files modified; head suite passes.",
    };
  }

  const behaviorChangesPath = path.join(root, ".verification", "behavior-changes.json");
  let declaredBehaviorChange = false;
  if (fs.existsSync(behaviorChangesPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(behaviorChangesPath, "utf8")) as { changes?: unknown[] };
      declaredBehaviorChange = Array.isArray(parsed.changes) && parsed.changes.length > 0;
    } catch {
      declaredBehaviorChange = false;
    }
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-oracle-"));
  const worktreeDir = path.join(tmpDir, "head-with-base-tests");
  try {
    const addWt = spawnSync("git", ["worktree", "add", "--detach", worktreeDir, "HEAD"], {
      cwd: root,
      encoding: "utf8",
    });
    if (addWt.status !== 0) {
      return {
        passed: false,
        baseRef,
        baseTestsOnHeadCodeExit: -1,
        headTestsOnHeadCodeExit: headExit,
        declaredBehaviorChange,
        reason: `Failed to create oracle worktree: ${(addWt.stderr ?? "").trim()}`,
      };
    }

    let restoredAnyBaseTest = false;
    for (const rel of changedTestFiles) {
      const baseContent = spawnSync("git", ["-C", root, "show", `${baseRef}:${rel}`], { encoding: "utf8" });
      if (baseContent.status === 0) {
        const dest = path.resolve(worktreeDir, rel);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, baseContent.stdout, "utf8");
        restoredAnyBaseTest = true;
      }
    }

    if (!restoredAnyBaseTest) {
      return {
        passed: true,
        baseRef,
        baseTestsOnHeadCodeExit: 0,
        headTestsOnHeadCodeExit: 0,
        declaredBehaviorChange,
        reason: "Only newly added test files in diff; base oracle preserved.",
      };
    }

    const baseOnHead = spawnSync(testCmd, [], { cwd: worktreeDir, shell: true, encoding: "utf8", timeout: 120_000 });
    const baseExit = baseOnHead.status ?? 1;
    const passed = baseExit === 0 || declaredBehaviorChange;
    return {
      passed,
      baseRef,
      baseTestsOnHeadCodeExit: baseExit,
      headTestsOnHeadCodeExit: headExit,
      declaredBehaviorChange,
      reason:
        baseExit === 0
          ? "Two-sided oracle PASS: base test suite still passes against head code."
          : declaredBehaviorChange
            ? "Two-sided oracle PASS: base tests failed against head code, explicitly approved in .verification/behavior-changes.json."
            : `ORACLE REWRITE DETECTED: base tests from ${baseRef} fail against head code (exit ${baseExit}) without an owner-approved .verification/behavior-changes.json entry.`,
    };
  } finally {
    spawnSync("git", ["worktree", "remove", "--force", worktreeDir], { cwd: root, encoding: "utf8" });
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
