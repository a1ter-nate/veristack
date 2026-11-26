import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isTestFilePath } from "../discover.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "./command-audit.ts";

export interface TwoSidedOracleResult {
  passed: boolean;
  baseRef: string;
  baseTestsOnHeadCodeExit: number;
  headTestsOnHeadCodeExit: number;
  declaredBehaviorChange: boolean;
  reason: string;
}

const ORACLE_CONFIG_SURFACE =
  /(?:^|\/)(?:package\.json|tsconfig(?:\.[^/]+)?\.json|bunfig\.toml|Cargo\.toml|\.cargo\/config\.toml|pyproject\.toml|pytest\.ini|setup\.cfg|tox\.ini|(?:vitest|vite|jest|playwright)\.config\.[cm]?[jt]s|jest\.config\.json|\.mocharc\.[^/]+|conftest\.py|Directory\.Build\.props|[^/]+\.csproj|\.verification\/rungs\.json)$|__snapshots__\/.*\.snap$|\.golden\.[^/]+$/i;

const TEST_DIR_SURFACE =
  /(?:^|\/)(?:tests|test|__tests__|spec|specs|testdata|fixtures|__fixtures__|golden|goldens|[^/]+\.(?:Tests|UnitTests|IntegrationTests))\//i;

function isOracleSurface(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  return isTestFilePath(norm) || TEST_DIR_SURFACE.test(norm) || ORACLE_CONFIG_SURFACE.test(norm);
}

function loadBaseApprovedBehaviorChanges(repoRoot: string, baseRef: string): Set<string> {
  const approved = new Set<string>();
  const baseShow = spawnSync("git", ["-C", repoRoot, "show", `${baseRef}:.verification/behavior-changes.json`], {
    encoding: "utf8",
  });
  if (baseShow.status !== 0) return approved;
  try {
    const parsed = JSON.parse(baseShow.stdout) as {
      changes?: Array<{ file?: string; reason?: string; approvedBy?: string }>;
    };
    if (!Array.isArray(parsed.changes)) return approved;
    for (const c of parsed.changes) {
      if (
        typeof c.file === "string" &&
        c.file.trim().length > 0 &&
        typeof c.reason === "string" &&
        c.reason.trim().length >= 8 &&
        typeof c.approvedBy === "string" &&
        c.approvedBy.startsWith("@")
      ) {
        approved.add(c.file.trim());
      }
    }
  } catch {
    return approved;
  }
  return approved;
}

function linkNodeModulesWorkspaceAware(absRoot: string, sandboxDir: string): void {
  const srcNm = path.join(absRoot, "node_modules");
  const dstNm = path.join(sandboxDir, "node_modules");
  if (!fs.existsSync(srcNm)) return;
  const linkDir = (srcDir: string, dstDir: string): void => {
    fs.mkdirSync(dstDir, { recursive: true });
    for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
      const sPath = path.join(srcDir, entry.name);
      const dPath = path.join(dstDir, entry.name);
      if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) {
        linkDir(sPath, dPath);
        continue;
      }
      if (entry.isSymbolicLink()) {
        try {
          const target = fs.realpathSync(sPath);
          if (target === absRoot || target.startsWith(`${absRoot}${path.sep}`)) {
            const rel = path.relative(absRoot, target);
            fs.symlinkSync(path.join(sandboxDir, rel), dPath);
            continue;
          }
        } catch {
          continue;
        }
      }
      try {
        fs.symlinkSync(sPath, dPath);
      } catch {
        continue;
      }
    }
  };
  linkDir(srcNm, dstNm);
}

function copyWorkingTreeToSandbox(repoRoot: string): string {
  const absRoot = fs.realpathSync(path.resolve(repoRoot));
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-oracle-"));
  const skipTop = new Set([".git", "node_modules", ".venv", "venv", "target"]);
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const src = path.join(absRoot, entry.name);
    const dst = path.join(sandboxDir, entry.name);
    if (skipTop.has(entry.name)) {
      if (entry.name === "node_modules") linkNodeModulesWorkspaceAware(absRoot, sandboxDir);
      else if (entry.name === ".venv" || entry.name === "venv") {
        try { fs.symlinkSync(src, dst); } catch { continue; }
      }
      continue;
    }
    fs.cpSync(src, dst, { recursive: true, dereference: false });
  }
  return sandboxDir;
}

export function runTwoSidedOracleCheck(
  repoPath: string,
  baseRef: string,
  testCmd: string,
): TwoSidedOracleResult {
  if (!baseRef || baseRef.startsWith("-")) {
    return {
      passed: false,
      baseRef: baseRef || "<missing>",
      baseTestsOnHeadCodeExit: -1,
      headTestsOnHeadCodeExit: -1,
      declaredBehaviorChange: false,
      reason: `Invalid or missing --base ref '${baseRef}'.`,
    };
  }
  const root = path.resolve(repoPath);
  const revCheck = spawnSync("git", ["-C", root, "rev-parse", "--verify", `${baseRef}^{commit}`], { encoding: "utf8" });
  if (revCheck.status !== 0) {
    return {
      passed: false,
      baseRef,
      baseTestsOnHeadCodeExit: -1,
      headTestsOnHeadCodeExit: -1,
      declaredBehaviorChange: false,
      reason: `git rev-parse failed for base ref '${baseRef}' — failing closed.`,
    };
  }

  const parsedCmd = parseAndValidateCommandArgv("canary", testCmd, root);
  if (parsedCmd.error) {
    return {
      passed: false,
      baseRef,
      baseTestsOnHeadCodeExit: -1,
      headTestsOnHeadCodeExit: -1,
      declaredBehaviorChange: false,
      reason: `Rejected oracle --test-cmd: ${parsedCmd.error}`,
    };
  }
  const childEnv = scrubChildEnv();
  const headRun = runArgvChain(parsedCmd.steps, root, childEnv, 120_000);
  const headExit = headRun.status;
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

  const diffFiles = spawnSync("git", ["-C", root, "diff", "--no-renames", "--name-only", baseRef, "--"], {
    encoding: "utf8",
  });
  if (diffFiles.status !== 0) {
    return {
      passed: false,
      baseRef,
      baseTestsOnHeadCodeExit: -1,
      headTestsOnHeadCodeExit: headExit,
      declaredBehaviorChange: false,
      reason: `git diff against '${baseRef}' failed — failing closed.`,
    };
  }

  const diffSet = new Set<string>(
    (diffFiles.stdout ?? "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && isOracleSurface(s)),
  );
  const untracked = spawnSync("git", ["-C", root, "ls-files", "--others", "--exclude-standard"], { encoding: "utf8" });
  if (untracked.status === 0) {
    for (const rel of (untracked.stdout ?? "").split(/\r?\n/).map((s) => s.trim())) {
      if (rel && isOracleSurface(rel)) diffSet.add(rel);
    }
  }
  const changedOracleFiles = [...diffSet].sort();

  if (changedOracleFiles.length === 0) {
    return {
      passed: true,
      baseRef,
      baseTestsOnHeadCodeExit: 0,
      headTestsOnHeadCodeExit: 0,
      declaredBehaviorChange: false,
      reason: "No existing test files or test runner configs modified; head suite passes.",
    };
  }

  const approvedFiles = loadBaseApprovedBehaviorChanges(root, baseRef);
  const allApproved = changedOracleFiles.every((f) => approvedFiles.has(f));

  const sandboxDir = copyWorkingTreeToSandbox(root);
  try {
    let restoredAnyBaseOracle = false;
    for (const rel of changedOracleFiles) {
      const baseContent = spawnSync("git", ["-C", root, "show", `${baseRef}:${rel}`], { maxBuffer: 32 * 1024 * 1024 });
      const dest = path.resolve(sandboxDir, rel);
      if (baseContent.status === 0) {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, baseContent.stdout);
        restoredAnyBaseOracle = true;
      } else if (fs.existsSync(dest)) {
        fs.rmSync(dest, { force: true });
      }
    }

    if (!restoredAnyBaseOracle) {
      return {
        passed: true,
        baseRef,
        baseTestsOnHeadCodeExit: 0,
        headTestsOnHeadCodeExit: 0,
        declaredBehaviorChange: false,
        reason: "Only newly added test files in diff; base oracle preserved.",
      };
    }

    const baseParsedCmd = parseAndValidateCommandArgv("canary", testCmd, sandboxDir);
    if (baseParsedCmd.error) {
      return {
        passed: false,
        baseRef,
        baseTestsOnHeadCodeExit: -1,
        headTestsOnHeadCodeExit: headExit,
        declaredBehaviorChange: false,
        reason: `Rejected base-ref oracle --test-cmd: ${baseParsedCmd.error}`,
      };
    }
    const baseOnHead = runArgvChain(baseParsedCmd.steps, sandboxDir, childEnv, 120_000);
    const baseExit = baseOnHead.status;
    const passed = baseExit === 0 || allApproved;
    return {
      passed,
      baseRef,
      baseTestsOnHeadCodeExit: baseExit,
      headTestsOnHeadCodeExit: headExit,
      declaredBehaviorChange: allApproved,
      reason:
        baseExit === 0
          ? "Two-sided oracle PASS: base tests and runner config still pass against working-tree code."
          : allApproved
            ? "Two-sided oracle PASS: base-ref .verification/behavior-changes.json explicitly approves modified oracle files."
            : `ORACLE REWRITE DETECTED: base tests/configs from ${baseRef} fail against working-tree code (exit ${baseExit}) without base-approved .verification/behavior-changes.json entries for [${changedOracleFiles.join(", ")}].`,
    };
  } finally {
    fs.rmSync(sandboxDir, { recursive: true, force: true });
  }
}
