import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isTestFilePath } from "../discover.ts";
import { maskCode } from "../test-lexical.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "./command-audit.ts";
import { runGitClean, runGitCleanBuffer } from "./config-audit.ts";
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
  /(?:^|\/)(?:\.gitattributes|package\.json|tsconfig(?:\.[^/]+)?\.json|bunfig\.toml|Cargo\.toml|\.cargo\/config(?:\.toml)?|\.config\/nextest\.toml|build\.rs|pyproject\.toml|pytest\.ini|\.pytest\.toml|pytest\.toml|setup\.cfg|tox\.ini|sitecustomize\.py|usercustomize\.py|conftest\.py|pytest\.py|unittest\.py|go\.mod|go\.work|babel\.config\.[^/]+|\.babelrc(?:\.[^/]+)?|\.swcrc|vitest\.workspace\.[cm]?[jt]s|(?:vitest|vite|jest|playwright|cypress|ava)\.config\.[cm]?[jt]s|jest\.config\.json|\.mocharc\.[^/]+|phpunit\.xml(?:\.dist)?|\.rspec|Directory\.Build\.(?:props|targets)|Directory\.Packages\.props|global\.json|[^/]+\.csproj|[^/]+\.runsettings|\.env(?:\.[^/]+)?|\.verification\/rungs\.json|examples\/[^/]+\/manifest\.json)$|__snapshots__\/.*\.snap$|\.golden\.[^/]+$/i;

const TEST_DIR_SURFACE =
  /(?:^|\/)(?:tests|test|__tests__|test-utils|testing|spec|specs|testdata|fixtures|__fixtures__|mocks|__mocks__|stubs|helpers|support|golden|goldens|[^/]+\.(?:Tests|UnitTests|IntegrationTests|Specs))\//i;

function isOracleSurface(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  return isTestFilePath(norm) || TEST_DIR_SURFACE.test(norm) || ORACLE_CONFIG_SURFACE.test(norm);
}

function listAllWorkingTreeOracleFiles(repoRoot: string): string[] {
  const out: string[] = [];
  const skipDirs = new Set([".git", "node_modules", ".venv", "venv", "target", "dist", "bin", "obj"]);
  const stack: Array<[string, string]> = [[repoRoot, ""]];
  while (stack.length > 0) {
    const pair = stack.pop();
    if (!pair) continue;
    const [dir, relPrefix] = pair;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) { out.push(rel); continue; }
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) stack.push([path.join(dir, entry.name), rel]);
      } else if (isOracleSurface(rel)) {
        out.push(rel);
      }
    }
  }
  return out;
}

function extractRustInlineTestSpans(raw: string): Array<{ start: number; end: number }> {
  const withTests = maskCode(raw, "rust", false);
  const prodOnly = maskCode(raw, "rust", "prod-strip-standalone-tests");
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
  const baseShow = runGitClean(repoRoot, ["show", `${baseRef}:.verification/behavior-changes.json`]);
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

function linkSingleWorkspaceNodeModule(
  entry: fs.Dirent,
  paths: { srcDir: string; dstDir: string; absRoot: string; sandboxDir: string },
  stack: Array<[string, string]>,
): void {
  const sPath = path.join(paths.srcDir, entry.name);
  const dPath = path.join(paths.dstDir, entry.name);
  if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) { stack.push([sPath, dPath]); return; }
  if (entry.isSymbolicLink()) {
    try {
      const target = fs.realpathSync(sPath);
      if (target === paths.absRoot || target.startsWith(`${paths.absRoot}${path.sep}`)) {
        fs.symlinkSync(path.join(paths.sandboxDir, path.relative(paths.absRoot, target)), dPath);
        return;
      }
    } catch { return; }
  }
  try { fs.symlinkSync(sPath, dPath); } catch { return; }
}

function linkNodeModulesWorkspaceAware(absRoot: string, sandboxDir: string): void {
  const srcNm = path.join(absRoot, "node_modules");
  const dstNm = path.join(sandboxDir, "node_modules");
  if (!fs.existsSync(srcNm)) return;
  const stack: Array<[string, string]> = [[srcNm, dstNm]];
  while (stack.length > 0) {
    const pair = stack.pop();
    if (!pair) continue;
    const [srcDir, dstDir] = pair;
    fs.mkdirSync(dstDir, { recursive: true });
    for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
      linkSingleWorkspaceNodeModule(entry, { srcDir, dstDir, absRoot, sandboxDir }, stack);
    }
  }
}

function copyWorkingTreeToSandbox(repoRoot: string): string {
  const absRoot = fs.realpathSync(path.resolve(repoRoot));
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-oracle-"));
  const skipDirs = new Set([".git", "node_modules", ".venv", "venv", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "obj"]);
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const src = path.join(absRoot, entry.name);
    const dst = path.join(sandboxDir, entry.name);
    if (skipDirs.has(entry.name)) {
      if (entry.name === "node_modules") linkNodeModulesWorkspaceAware(absRoot, sandboxDir);
      else if (entry.name === ".venv" || entry.name === "venv") { try { fs.symlinkSync(src, dst); } catch { continue; } }
      continue;
    }
    fs.cpSync(src, dst, { recursive: true, dereference: false, filter: (p) => p === src || !skipDirs.has(path.basename(p)) });
  }
  return sandboxDir;
}

function safeWriteInSandbox(sandboxDir: string, rel: string, data: string | Buffer): void {
  const realSb = fs.realpathSync(sandboxDir);
  const dest = path.resolve(realSb, rel);
  if (dest !== realSb && !dest.startsWith(`${realSb}${path.sep}`)) return;
  try {
    if (fs.lstatSync(dest).isSymbolicLink()) fs.unlinkSync(dest);
  } catch { void 0; }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const realParent = fs.realpathSync(path.dirname(dest));
  if (realParent !== realSb && !realParent.startsWith(`${realSb}${path.sep}`)) return;
  fs.writeFileSync(dest, data);
}

function makeSandboxPythonEnv(baseEnv: NodeJS.ProcessEnv, sandboxDir: string, homeDir: string): NodeJS.ProcessEnv {
  const pyPaths = [path.join(sandboxDir, "src"), sandboxDir].filter((p) => fs.existsSync(p));
  if (baseEnv.PYTHONPATH) pyPaths.push(baseEnv.PYTHONPATH);
  return { ...baseEnv, HOME: homeDir, XDG_CONFIG_HOME: homeDir, TMPDIR: homeDir, TMP: homeDir, TEMP: homeDir, PYTHONPATH: pyPaths.join(path.delimiter) };
}

function collectRustInlineSplices(
  root: string,
  baseRef: string,
  rustInlineCandidates: readonly string[],
): { splices: Array<{ rel: string; spliced: string }>; deletedRustWithTests: boolean } {
  const splices: Array<{ rel: string; spliced: string }> = [];
  let deletedRustWithTests = false;
  for (const rel of rustInlineCandidates) {
    const baseShow = runGitClean(root, ["show", `${baseRef}:${rel}`]);
    if (baseShow.status !== 0) continue;
    const headAbs = path.join(root, rel);
    if (fs.existsSync(headAbs)) {
      const spliced = spliceBaseRustTestsIntoHead(fs.readFileSync(headAbs, "utf8"), baseShow.stdout);
      if (spliced !== null) splices.push({ rel, spliced });
    } else if (extractRustInlineTestSpans(baseShow.stdout).length > 0) {
      deletedRustWithTests = true;
      splices.push({ rel, spliced: baseShow.stdout });
    }
  }
  return { splices, deletedRustWithTests };
}

function runBaseOracleSandbox(input: {
  root: string;
  baseRef: string;
  testCmd: string;
  headExit: number;
  changedOracleFiles: readonly string[];
  rustInlineSplices: ReadonlyArray<{ rel: string; spliced: string }>;
  allCheckedOracle: readonly string[];
  allApproved: boolean;
  childEnv: NodeJS.ProcessEnv;
}): TwoSidedOracleResult {
  const { root, baseRef, testCmd, headExit, changedOracleFiles, rustInlineSplices, allCheckedOracle, allApproved, childEnv } = input;
  const sandboxDir = copyWorkingTreeToSandbox(root);
  const isolatedHome = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-oh-"));
  try {
    for (const rel of changedOracleFiles) {
      const baseContent = runGitCleanBuffer(root, ["show", `${baseRef}:${rel}`]);
      const dest = path.resolve(sandboxDir, rel);
      if (baseContent.status === 0) safeWriteInSandbox(sandboxDir, rel, baseContent.stdout);
      else try { fs.rmSync(dest, { recursive: true, force: true }); } catch { void 0; }
    }
    for (const splice of rustInlineSplices) safeWriteInSandbox(sandboxDir, splice.rel, splice.spliced);

    const baseParsedCmd = parseAndValidateCommandArgv("canary", testCmd, sandboxDir);
    if (baseParsedCmd.error) {
      return { passed: false, baseRef, baseTestsOnHeadCodeExit: -1, headTestsOnHeadCodeExit: headExit, declaredBehaviorChange: false, reason: `Rejected base-ref oracle --test-cmd: ${baseParsedCmd.error}` };
    }
    const baseOnHead = runArgvChain(baseParsedCmd.steps, { cwd: sandboxDir, env: makeSandboxPythonEnv(childEnv, sandboxDir, isolatedHome), timeoutMs: 120_000, stepCwds: baseParsedCmd.stepCwds });
    const baseCounts = parseRunnerTestCounts(`${baseOnHead.stdout}\n${baseOnHead.stderr}`, baseParsedCmd.steps);
    const baseRanZero = baseOnHead.status === 0 && baseCounts.hasTestRunner && (!baseCounts.matched || baseCounts.passed <= 0 || baseCounts.failed > 0);
    const effectiveBaseExit = baseRanZero ? 1 : baseOnHead.status;
    return {
      passed: effectiveBaseExit === 0 || allApproved, baseRef, baseTestsOnHeadCodeExit: effectiveBaseExit,
      headTestsOnHeadCodeExit: headExit, declaredBehaviorChange: allApproved,
      reason:
        effectiveBaseExit === 0
          ? "Two-sided oracle PASS: base tests and runner config still pass against working-tree code."
          : allApproved
            ? "Two-sided oracle PASS: base-ref .verification/behavior-changes.json explicitly approves modified oracle files."
            : baseRanZero
              ? "ORACLE REWRITE DETECTED: base oracle executed 0 passing tests against working-tree code."
              : `ORACLE REWRITE DETECTED: base tests/configs from ${baseRef} fail against working-tree code (exit ${effectiveBaseExit}) without base-approved .verification/behavior-changes.json entries for [${allCheckedOracle.join(", ")}].`,
    };
  } finally {
    fs.rmSync(sandboxDir, { recursive: true, force: true });
    fs.rmSync(isolatedHome, { recursive: true, force: true });
  }
}

export function runTwoSidedOracleCheck(repoPath: string, baseRef: string, testCmd: string): TwoSidedOracleResult {
  const fail = (headExit: number, baseExit: number, reason: string): TwoSidedOracleResult => ({
    passed: false, baseRef: baseRef || "<missing>", baseTestsOnHeadCodeExit: baseExit,
    headTestsOnHeadCodeExit: headExit, declaredBehaviorChange: false, reason,
  });
  if (!baseRef || baseRef.startsWith("-")) return fail(-1, -1, `Invalid or missing --base ref '${baseRef}'.`);
  const root = path.resolve(repoPath);
  if (runGitClean(root, ["rev-parse", "--verify", `${baseRef}^{commit}`]).status !== 0) return fail(-1, -1, `git rev-parse failed for base ref '${baseRef}' — failing closed.`);
  const diffFiles = runGitClean(root, ["diff", "--no-renames", "--name-only", baseRef, "--"]);
  if (diffFiles.status !== 0) return fail(-1, -1, `git diff against '${baseRef}' failed — failing closed.`);
  const allDiffPaths = (diffFiles.stdout ?? "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const diffSet = new Set<string>(allDiffPaths.filter((s) => isOracleSurface(s)));
  const rustInlineCandidates = allDiffPaths.filter((s) => s.endsWith(".rs") && !diffSet.has(s));
  const trackedAtBase = new Set((runGitClean(root, ["ls-tree", "-r", "--name-only", baseRef]).stdout ?? "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
  for (const rel of listAllWorkingTreeOracleFiles(root)) if (!trackedAtBase.has(rel)) diffSet.add(rel);

  const parsedCmd = parseAndValidateCommandArgv("canary", testCmd, root);
  if (parsedCmd.error) return fail(-1, -1, `Rejected oracle --test-cmd: ${parsedCmd.error}`);
  const childEnv = scrubChildEnv();
  const headSandboxDir = copyWorkingTreeToSandbox(root);
  const headHome = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-oh-head-"));
  let headRun: ReturnType<typeof runArgvChain>;
  try {
    headRun = runArgvChain(parsedCmd.steps, { cwd: headSandboxDir, env: makeSandboxPythonEnv(childEnv, headSandboxDir, headHome), timeoutMs: 120_000, stepCwds: parsedCmd.stepCwds });
  } finally {
    fs.rmSync(headSandboxDir, { recursive: true, force: true });
    fs.rmSync(headHome, { recursive: true, force: true });
  }
  if (headRun.status !== 0) return fail(headRun.status, -1, `Head test suite fails (exit ${headRun.status}).`);
  const headCounts = parseRunnerTestCounts(`${headRun.stdout}\n${headRun.stderr}`, parsedCmd.steps);
  if (headCounts.hasTestRunner && (!headCounts.matched || headCounts.passed <= 0 || headCounts.failed > 0)) {
    return fail(headRun.status, -1, `Head test suite executed 0 passing tests (matched=${headCounts.matched}, passed=${headCounts.passed}).`);
  }
  const changedOracleFiles = [...diffSet].sort();
  const { splices: rustInlineSplices, deletedRustWithTests } = collectRustInlineSplices(root, baseRef, rustInlineCandidates);
  if (changedOracleFiles.length === 0 && rustInlineSplices.length === 0) {
    return { passed: true, baseRef, baseTestsOnHeadCodeExit: 0, headTestsOnHeadCodeExit: 0, declaredBehaviorChange: false, reason: "No existing test files or test runner configs modified; head suite passes." };
  }
  const allCheckedOracle = [...changedOracleFiles, ...rustInlineSplices.map((r) => r.rel)];
  const approvedFiles = loadBaseApprovedBehaviorChanges(root, baseRef);
  const allApproved = allCheckedOracle.every((f) => approvedFiles.has(f));
  if (deletedRustWithTests && !allApproved) {
    return fail(headRun.status, 1, `ORACLE REWRITE DETECTED: Rust file(s) containing inline tests were deleted compared to ${baseRef} without base-approved .verification/behavior-changes.json.`);
  }
  return runBaseOracleSandbox({ root, baseRef, testCmd, headExit: headRun.status, changedOracleFiles, rustInlineSplices, allCheckedOracle, allApproved, childEnv });
}
