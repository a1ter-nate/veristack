import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isTestFilePath } from "../discover.ts";
import { maskCode } from "../test-lexical.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "./command-audit.ts";
import { parseRunnerTestCounts } from "./runner-metrics.ts";

export interface TwoSidedOracleResult {
  passed: boolean;
  baseRef: string;
  baseTestsOnHeadCodeExit: number;
  headTestsOnHeadCodeExit: number;
  declaredBehaviorChange: boolean;
  reason: string;
}

const ORACLE_CONFIG_SURFACE =
  /(?:^|\/)(?:package\.json|tsconfig(?:\.[^/]+)?\.json|bunfig\.toml|Cargo\.toml|\.cargo\/config\.toml|pyproject\.toml|pytest\.ini|pytest\.toml|setup\.cfg|tox\.ini|sitecustomize\.py|conftest\.py|go\.mod|babel\.config\.[cm]?[jt]s|vitest\.workspace\.[cm]?[jt]s|(?:vitest|vite|jest|playwright)\.config\.[cm]?[jt]s|jest\.config\.json|\.mocharc\.[^/]+|Directory\.Build\.props|Directory\.Packages\.props|[^/]+\.csproj|[^/]+\.runsettings|\.env\.test|\.verification\/rungs\.json)$|__snapshots__\/.*\.snap$|\.golden\.[^/]+$/i;

const TEST_DIR_SURFACE =
  /(?:^|\/)(?:tests|test|__tests__|spec|specs|testdata|fixtures|__fixtures__|golden|goldens|[^/]+\.(?:Tests|UnitTests|IntegrationTests|Specs))\//i;

function isOracleSurface(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  return isTestFilePath(norm) || TEST_DIR_SURFACE.test(norm) || ORACLE_CONFIG_SURFACE.test(norm);
}

function extractRustInlineTestSpans(raw: string): Array<{ start: number; end: number }> {
  const withTests = maskCode(raw, "rust", false);
  const prodOnly = maskCode(raw, "rust", true);
  const spans: Array<{ start: number; end: number }> = [];
  let inRegion = false;
  let start = -1;
  let lastDiff = -1;
  for (let i = 0; i < raw.length; i++) {
    const a = withTests[i] ?? " ";
    const b = prodOnly[i] ?? " ";
    if (a !== b) {
      if (!inRegion) { inRegion = true; start = i; }
      lastDiff = i;
    } else if (inRegion && b !== " " && b !== "\n" && b !== "\r" && b !== "\t") {
      spans.push({ start, end: lastDiff + 1 });
      inRegion = false;
    }
  }
  if (inRegion && lastDiff >= start) spans.push({ start, end: lastDiff + 1 });
  return spans;
}

function spliceBaseRustTestsIntoHead(headRaw: string, baseRaw: string): string | null {
  const baseSpans = extractRustInlineTestSpans(baseRaw);
  if (baseSpans.length === 0) return null;
  const headSpans = extractRustInlineTestSpans(headRaw);
  let prodHead = "";
  let cursor = 0;
  for (const sp of headSpans) {
    prodHead += headRaw.slice(cursor, sp.start);
    cursor = sp.end;
  }
  prodHead += headRaw.slice(cursor);
  const baseTestBlocks = baseSpans.map((sp) => baseRaw.slice(sp.start, sp.end)).join("\n\n");
  return `${prodHead}\n\n${baseTestBlocks}\n`;
}

function loadBaseApprovedBehaviorChanges(repoRoot: string, baseRef: string): Set<string> {
  const approved = new Set<string>();
  const baseShow = spawnSync("git", ["-C", repoRoot, "show", `${baseRef}:.verification/behavior-changes.json`], { encoding: "utf8" });
  if (baseShow.status !== 0) return approved;
  try {
    const parsed = JSON.parse(baseShow.stdout) as { changes?: Array<{ file?: string; reason?: string; approvedBy?: string }> };
    if (!Array.isArray(parsed.changes)) return approved;
    for (const c of parsed.changes) {
      if (typeof c.file === "string" && c.file.trim().length > 0 && typeof c.reason === "string" && c.reason.trim().length >= 8 && typeof c.approvedBy === "string" && c.approvedBy.startsWith("@")) {
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
      if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) { linkDir(sPath, dPath); continue; }
      if (entry.isSymbolicLink()) {
        try {
          const target = fs.realpathSync(sPath);
          if (target === absRoot || target.startsWith(`${absRoot}${path.sep}`)) {
            fs.symlinkSync(path.join(sandboxDir, path.relative(absRoot, target)), dPath);
            continue;
          }
        } catch { continue; }
      }
      try { fs.symlinkSync(sPath, dPath); } catch { continue; }
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
      else if (entry.name === ".venv" || entry.name === "venv") { try { fs.symlinkSync(src, dst); } catch { continue; } }
      continue;
    }
    fs.cpSync(src, dst, { recursive: true, dereference: false });
  }
  return sandboxDir;
}

function makeSandboxPythonEnv(baseEnv: NodeJS.ProcessEnv, sandboxDir: string): NodeJS.ProcessEnv {
  const pyPaths = [path.join(sandboxDir, "src"), sandboxDir].filter((p) => fs.existsSync(p));
  if (baseEnv.PYTHONPATH) pyPaths.push(baseEnv.PYTHONPATH);
  return { ...baseEnv, PYTHONPATH: pyPaths.join(path.delimiter) };
}

export function runTwoSidedOracleCheck(repoPath: string, baseRef: string, testCmd: string): TwoSidedOracleResult {
  const fail = (headExit: number, baseExit: number, reason: string): TwoSidedOracleResult => ({
    passed: false, baseRef: baseRef || "<missing>", baseTestsOnHeadCodeExit: baseExit,
    headTestsOnHeadCodeExit: headExit, declaredBehaviorChange: false, reason,
  });
  if (!baseRef || baseRef.startsWith("-")) return fail(-1, -1, `Invalid or missing --base ref '${baseRef}'.`);
  const root = path.resolve(repoPath);
  const revCheck = spawnSync("git", ["-C", root, "rev-parse", "--verify", `${baseRef}^{commit}`], { encoding: "utf8" });
  if (revCheck.status !== 0) return fail(-1, -1, `git rev-parse failed for base ref '${baseRef}' — failing closed.`);

  const parsedCmd = parseAndValidateCommandArgv("canary", testCmd, root);
  if (parsedCmd.error) return fail(-1, -1, `Rejected oracle --test-cmd: ${parsedCmd.error}`);
  const childEnv = scrubChildEnv();
  const headRun = runArgvChain(parsedCmd.steps, root, childEnv, 120_000);
  const headExit = headRun.status;
  if (headExit !== 0) return fail(headExit, -1, `Head test suite fails (exit ${headExit}).`);
  const headCounts = parseRunnerTestCounts(`${headRun.stdout}\n${headRun.stderr}`, parsedCmd.steps);
  if (headCounts.hasTestRunner && (!headCounts.matched || headCounts.passed <= 0 || headCounts.failed > 0)) {
    return fail(headExit, -1, `Head test suite executed 0 passing tests (matched=${headCounts.matched}, passed=${headCounts.passed}).`);
  }

  const diffFiles = spawnSync("git", ["-C", root, "diff", "--no-renames", "--name-only", baseRef, "--"], { encoding: "utf8" });
  if (diffFiles.status !== 0) return fail(headExit, -1, `git diff against '${baseRef}' failed — failing closed.`);

  const allDiffPaths = (diffFiles.stdout ?? "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const diffSet = new Set<string>(allDiffPaths.filter((s) => isOracleSurface(s)));
  const rustInlineCandidates = allDiffPaths.filter((s) => s.endsWith(".rs") && !diffSet.has(s));
  const untracked = spawnSync("git", ["-C", root, "ls-files", "--others", "--exclude-standard"], { encoding: "utf8" });
  if (untracked.status === 0) {
    for (const rel of (untracked.stdout ?? "").split(/\r?\n/).map((s) => s.trim())) {
      if (rel && isOracleSurface(rel)) diffSet.add(rel);
    }
  }
  const changedOracleFiles = [...diffSet].sort();
  const rustInlineSplices: Array<{ rel: string; spliced: string }> = [];
  for (const rel of rustInlineCandidates) {
    const baseShow = spawnSync("git", ["-C", root, "show", `${baseRef}:${rel}`], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    const headAbs = path.join(root, rel);
    if (baseShow.status === 0 && fs.existsSync(headAbs)) {
      const spliced = spliceBaseRustTestsIntoHead(fs.readFileSync(headAbs, "utf8"), baseShow.stdout);
      if (spliced !== null) rustInlineSplices.push({ rel, spliced });
    }
  }

  if (changedOracleFiles.length === 0 && rustInlineSplices.length === 0) {
    return {
      passed: true, baseRef, baseTestsOnHeadCodeExit: 0, headTestsOnHeadCodeExit: 0,
      declaredBehaviorChange: false, reason: "No existing test files or test runner configs modified; head suite passes.",
    };
  }

  const allCheckedOracle = [...changedOracleFiles, ...rustInlineSplices.map((r) => r.rel)];
  const approvedFiles = loadBaseApprovedBehaviorChanges(root, baseRef);
  const allApproved = allCheckedOracle.every((f) => approvedFiles.has(f));

  const sandboxDir = copyWorkingTreeToSandbox(root);
  try {
    for (const rel of changedOracleFiles) {
      const baseContent = spawnSync("git", ["-C", root, "show", `${baseRef}:${rel}`], { maxBuffer: 32 * 1024 * 1024 });
      const dest = path.resolve(sandboxDir, rel);
      if (baseContent.status === 0) {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, baseContent.stdout);
      } else if (fs.existsSync(dest)) {
        fs.rmSync(dest, { force: true });
      }
    }
    for (const splice of rustInlineSplices) {
      const dest = path.resolve(sandboxDir, splice.rel);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, splice.spliced, "utf8");
    }

    const baseParsedCmd = parseAndValidateCommandArgv("canary", testCmd, sandboxDir);
    if (baseParsedCmd.error) return fail(headExit, -1, `Rejected base-ref oracle --test-cmd: ${baseParsedCmd.error}`);
    const baseOnHead = runArgvChain(baseParsedCmd.steps, sandboxDir, makeSandboxPythonEnv(childEnv, sandboxDir), 120_000);
    const baseExit = baseOnHead.status;
    const baseCounts = parseRunnerTestCounts(`${baseOnHead.stdout}\n${baseOnHead.stderr}`, baseParsedCmd.steps);
    const baseRanZero = baseExit === 0 && baseCounts.hasTestRunner && (!baseCounts.matched || baseCounts.passed <= 0 || baseCounts.failed > 0);
    const effectiveBaseExit = baseRanZero ? 1 : baseExit;
    const passed = effectiveBaseExit === 0 || allApproved;
    return {
      passed, baseRef, baseTestsOnHeadCodeExit: effectiveBaseExit, headTestsOnHeadCodeExit: headExit,
      declaredBehaviorChange: allApproved,
      reason:
        effectiveBaseExit === 0
          ? "Two-sided oracle PASS: base tests and runner config still pass against working-tree code."
          : allApproved
            ? "Two-sided oracle PASS: base-ref .verification/behavior-changes.json explicitly approves modified oracle files."
            : baseRanZero
              ? `ORACLE REWRITE DETECTED: base oracle executed 0 passing tests against working-tree code.`
              : `ORACLE REWRITE DETECTED: base tests/configs from ${baseRef} fail against working-tree code (exit ${effectiveBaseExit}) without base-approved .verification/behavior-changes.json entries for [${allCheckedOracle.join(", ")}].`,
    };
  } finally {
    fs.rmSync(sandboxDir, { recursive: true, force: true });
  }
}
