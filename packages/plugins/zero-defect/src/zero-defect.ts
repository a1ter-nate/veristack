import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DiscoveredRepo } from "@veristack/plugin";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "@veristack/plugin-control-plane";
import { runGitClean } from "@veristack/plugin-control-plane";
import { parseRunnerTestCounts } from "@veristack/plugin-canary";
import type { Finding, RungId } from "@veristack/plugin";
import { auditFormalSync } from "@veristack/plugin-laws-formal";
import { auditLaws } from "@veristack/plugin-laws-formal";
import { generateMcdcVectors, type McdcResult, type McdcVector } from "./mcdc.ts";

export { generateMcdcVectors, type McdcResult, type McdcVector };

export interface SpcResult {
  metric: string;
  count: number;
  mean: number;
  stdDev: number;
  upperSpecLimit: number;
  cpk: number | null;
  nelsonRule2Breach: boolean;
  nelsonRule3Breach: boolean;
  cpkBreach: boolean;
  status: "in_control" | "drift_warning" | "spec_breach";
  reasons: string[];
}

export interface RedBeforeFixResult {
  passed: boolean;
  baseRef: string;
  copiedTestFiles: string[];
  baseExitCode: number;
  headExitCode: number;
  reason: string;
}

const RUNG_ORDER: Record<RungId, number> = {
  R0: 0,
  R1: 1,
  R2: 2,
  R3: 3,
  R4: 4,
  R5: 5,
  R6: 6,
  R7: 7,
  R8: 8,
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function auditControlPlanFile(
  planFile: DiscoveredRepo["files"][number],
  allPathSet: ReadonlySet<string>,
  testText: string,
  findings: Finding[],
): void {
  if (!planFile.content) return;
  let parsed: unknown;
  try { parsed = JSON.parse(planFile.content); } catch {
    findings.push({ id: `ZD:fmea-json:${planFile.rel}`, rule: "fmea-invalid-json", category: "oracle-lock", rung: "R1", severity: "error", file: planFile.rel, line: 1, message: `${planFile.rel} is not valid JSON.`, fix: "Fix JSON syntax in the FMEA Control Plan." });
    return;
  }
  const entries = isRecord(parsed) && Array.isArray(parsed.controls) ? parsed.controls : [];
  for (const raw of entries) {
    if (!isRecord(raw)) continue;
    const id = typeof raw.id === "string" ? raw.id : "unknown";
    const severity = typeof raw.severity === "number" ? raw.severity : 0;
    const maxRung = typeof raw.maxAllowedRung === "string" ? (raw.maxAllowedRung as RungId) : "R8";
    const controlRef = typeof raw.controlRef === "string" ? raw.controlRef : "";
    const reqId = typeof raw.reqId === "string" ? raw.reqId : undefined;
    if (severity >= 8 && (RUNG_ORDER[maxRung] ?? 8) > RUNG_ORDER.R4) {
      findings.push({ id: `ZD:fmea-rung:${id}`, rule: "fmea-high-severity-rung", category: "oracle-lock", rung: "R1", severity: "error", file: planFile.rel, line: 1, message: `Control Plan entry '${id}' has severity ${severity} (>= 8) but allows detection at ${maxRung} (> R4).`, fix: "Push high-severity controls down to R0–R4 (type, lint, table, MBT, or real-engine test)." });
    }
    const refPath = controlRef.split("#")[0]?.trim() ?? "";
    if (!refPath || !allPathSet.has(refPath)) {
      findings.push({ id: `ZD:fmea-orphan:${id}`, rule: "fmea-orphaned-control", category: "oracle-lock", rung: "R1", severity: "error", file: planFile.rel, line: 1, message: `Control Plan entry '${id}' references missing control artifact '${controlRef}'.`, fix: "Restore the missing verification control or update the Control Plan with a live replacement." });
    }
    if (reqId && !testText.includes(reqId)) {
      findings.push({ id: `ZD:req-untraced:${reqId}`, rule: "traceability-unverified-requirement", category: "oracle-lock", rung: "R1", severity: "error", file: planFile.rel, line: 1, message: `Requirement '${reqId}' in Control Plan '${id}' has no linked test tag or fixture reference.`, fix: `Tag at least one executable test with '${reqId}' to maintain bidirectional traceability.` });
    }
  }
}

function auditEscapeLedgerFile(
  escapeFile: DiscoveredRepo["files"][number],
  allPathSet: ReadonlySet<string>,
  findings: Finding[],
): void {
  if (!escapeFile.content) return;
  let parsed: unknown;
  try { parsed = JSON.parse(escapeFile.content); } catch {
    findings.push({ id: `ZD:escape-json:${escapeFile.rel}`, rule: "a3-invalid-json", category: "oracle-lock", rung: "R1", severity: "error", file: escapeFile.rel, line: 1, message: `${escapeFile.rel} is not valid JSON.`, fix: "Fix JSON syntax in the A3 escape ledger." });
    return;
  }
  const records = isRecord(parsed) && Array.isArray(parsed.escapes) ? parsed.escapes : [];
  const byClass = new Map<string, Array<{ id: string; pokaYokeRef: string }>>();
  for (const raw of records) {
    if (!isRecord(raw) || typeof raw.defectClass !== "string") continue;
    const list = byClass.get(raw.defectClass) ?? [];
    list.push({ id: typeof raw.id === "string" ? raw.id : "?", pokaYokeRef: typeof raw.pokaYokeRef === "string" ? raw.pokaYokeRef.trim() : "" });
    byClass.set(raw.defectClass, list);
  }
  for (const [defectClass, list] of byClass.entries()) {
    if (list.length < 2) continue;
    const hasValidPokaYoke = list.some((entry) => {
      const refPath = entry.pokaYokeRef.split("#")[0]?.trim() ?? "";
      return refPath.length > 0 && allPathSet.has(refPath);
    });
    if (!hasValidPokaYoke) {
      findings.push({ id: `ZD:a3-repeat:${defectClass}`, rule: "a3-repeat-defect-no-poka-yoke", category: "oracle-lock", rung: "R1", severity: "error", file: escapeFile.rel, line: 1, message: `Escaped defect class '${defectClass}' occurred ${list.length} times without an R0/R1 Poka-Yoke lint/type check in pokaYokeRef.`, fix: "Add a deterministic R0/R1 compiler/lint check for this defect class and link its file path in pokaYokeRef." });
    }
  }
}

export function auditZeroDefectArtifacts(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  const allPathSet = new Set(repo.allRelPaths);
  const testText = repo.files.filter((f) => f.isTest).map((f) => f.content).join("\n");
  const planFile = repo.files.find((f) => f.rel === ".verification/control-plan.json" || f.rel === "control-plan.json");
  if (planFile) auditControlPlanFile(planFile, allPathSet, testText, findings);
  const escapeFile = repo.files.find((f) => f.rel === ".verification/escapes.json" || f.rel === "escapes.json");
  if (escapeFile) auditEscapeLedgerFile(escapeFile, allPathSet, findings);
  findings.push(...auditFormalSync(repo));
  findings.push(...auditLaws(repo).findings);
  return findings;
}

function detectNelsonBreaches(values: readonly number[], mean: number, stdDev: number): { rule1: boolean; rule2: boolean; rule3: boolean } {
  const sortedVals = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sortedVals.length / 2);
  const median = sortedVals.length % 2 === 0 ? ((sortedVals[mid - 1] ?? 0) + (sortedVals[mid] ?? 0)) / 2 : (sortedVals[mid] ?? 0);
  const absDevs = sortedVals.map((v) => Math.abs(v - median)).sort((a, b) => a - b);
  const mad = absDevs.length % 2 === 0 ? ((absDevs[mid - 1] ?? 0) + (absDevs[mid] ?? 0)) / 2 : (absDevs[mid] ?? 0);
  let consecAbove = 0; let rule2 = false;
  let consecRising = 1; let rule3 = false;
  let rule1 = false;
  for (let i = 0; i < values.length; i++) {
    const cur = values[i] ?? 0;
    if (stdDev > 0 && cur > mean + 3 * stdDev) rule1 = true;
    if (!rule1 && values.length >= 4) {
      if (mad > 0 && (0.6745 * (cur - median)) / mad > 3.5) rule1 = true;
      else if (mad === 0 && Math.abs(cur - median) > Math.max(1, Math.abs(median) * 0.5)) rule1 = true;
    }
    if (cur > mean) { consecAbove += 1; if (consecAbove >= 7) rule2 = true; } else { consecAbove = 0; }
    if (i > 0 && cur > (values[i - 1] ?? 0)) { consecRising += 1; if (consecRising >= 6) rule3 = true; } else if (i > 0) { consecRising = 1; }
  }
  return { rule1, rule2, rule3 };
}

export function evaluateSpcSeries(metric: string, values: readonly number[], upperSpecLimit: number): SpcResult {
  const invalidFail = (reason: string): SpcResult => ({
    metric, count: Array.isArray(values) ? values.length : 0, mean: 0, stdDev: 0, upperSpecLimit, cpk: null,
    nelsonRule2Breach: false, nelsonRule3Breach: false, cpkBreach: false, status: "spec_breach", reasons: [reason],
  });
  if (!Number.isFinite(upperSpecLimit)) return invalidFail(`Invalid upperSpecLimit (${String(upperSpecLimit)}); must be a finite number.`);
  if (!Array.isArray(values) || values.length < 3) return invalidFail(`SPC requires at least 3 finite observations (received ${Array.isArray(values) ? values.length : 0}).`);
  if (values.some((v) => typeof v !== "number" || !Number.isFinite(v))) return invalidFail("SPC series contains non-numeric or non-finite values.");

  const mean = values.reduce((acc, v) => acc + v, 0) / values.length;
  const variance = values.reduce((acc, v) => acc + (v - mean) ** 2, 0) / (values.length - 1);
  const stdDev = Math.sqrt(variance);
  const cpk = stdDev > 0 ? Number(((upperSpecLimit - mean) / (3 * stdDev)).toFixed(3)) : null;
  const nelson = detectNelsonBreaches(values, mean, stdDev);
  const latest = values[values.length - 1] ?? 0;
  const cpkBreach = cpk !== null && cpk < 1.33;
  const reasons: string[] = [];
  if (latest > upperSpecLimit) reasons.push(`Latest value ${latest} exceeds USL ${upperSpecLimit}.`);
  if (nelson.rule1) reasons.push("Nelson Rule 1: observation exceeds mean + 3*sigma control limit.");
  if (nelson.rule2) reasons.push("Nelson Rule 2: >= 7 consecutive points above historical mean.");
  if (nelson.rule3) reasons.push("Nelson Rule 3: >= 6 consecutive monotonically worsening points.");
  if (cpkBreach && cpk !== null) reasons.push(`Process capability Cpk=${cpk} dropped below 1.33 headroom floor.`);
  const status: SpcResult["status"] = latest > upperSpecLimit ? "spec_breach" : reasons.length > 0 ? "drift_warning" : "in_control";
  return { metric, count: values.length, mean: Number(mean.toFixed(4)), stdDev: Number(stdDev.toFixed(4)), upperSpecLimit, cpk, nelsonRule2Breach: nelson.rule2, nelsonRule3Breach: nelson.rule3, cpkBreach, status, reasons };
}

export function computeRolledThroughputYield(firstPassRates: readonly number[]): {
  rty: number;
  lowestStageIndex: number;
  lowestStageYield: number;
  belowFloor: boolean;
} {
  if (firstPassRates.length === 0) {
    return { rty: 1, lowestStageIndex: -1, lowestStageYield: 1, belowFloor: false };
  }
  let rty = 1;
  let lowestIdx = 0;
  let lowestVal = firstPassRates[0] ?? 1;
  for (const [idx, rate] of firstPassRates.entries()) {
    const clamped = Math.max(0, Math.min(1, rate));
    rty *= clamped;
    if (clamped < lowestVal) {
      lowestVal = clamped;
      lowestIdx = idx;
    }
  }
  return {
    rty: Number(rty.toFixed(4)),
    lowestStageIndex: lowestIdx,
    lowestStageYield: lowestVal,
    belowFloor: rty < 0.85 || lowestVal < 0.95,
  };
}

const INVALID_RED_ERROR =
  /\b(?:SyntaxError|ReferenceError|NameError|Cannot\s+find\s+module|TS\d{4}:|CS\d{4}:|error\[E\d{4}\]|IndentationError|ImportError)\b|\bundefined:\s+[A-Za-z_]/;

export { runTwoSidedOracleCheck, type TwoSidedOracleResult } from "@veristack/plugin-canary";

function collectChangedTestFiles(root: string, baseRef: string): string[] {
  const changed = runGitClean(root, ["status", "--porcelain", "-uall"]);
  const diffNames = runGitClean(root, ["diff", "--name-only", baseRef, "--"]);
  const candidates = new Set<string>();
  for (const line of `${changed.stdout ?? ""}\n${diffNames.stdout ?? ""}`.split(/\r?\n/)) {
    const cleaned = line.replace(/^[ MADRCU?!]{1,2}\s+/, "").trim();
    if (!cleaned) continue;
    if (/(?:^|\/)(?:tests?|__tests__|spec)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.(?:py|rs|go)$|(?:^|\/)test_[^/]+\.py$|Tests?\.cs$/i.test(cleaned)) {
      candidates.add(cleaned);
    }
  }
  return [...candidates].filter((rel) => {
    const p = path.join(root, rel);
    return fs.existsSync(p) && fs.statSync(p).isFile();
  });
}

function summarizeRedBeforeFixRuns(input: {
  baseRun: ReturnType<typeof runArgvChain>;
  headRun: ReturnType<typeof runArgvChain>;
  steps: string[][];
  baseRef: string;
  copiedTestFiles: string[];
}): RedBeforeFixResult {
  const { baseRun, headRun, steps, baseRef, copiedTestFiles } = input;
  const baseCode = baseRun.status ?? 1;
  const headCode = headRun.status ?? 1;
  const baseOut = `${baseRun.stdout ?? ""}\n${baseRun.stderr ?? ""}`;
  const headOut = `${headRun.stdout ?? ""}\n${headRun.stderr ?? ""}`;
  const headCounts = parseRunnerTestCounts(headOut, steps);
  const isDirectScript = steps.every((s) => (s[0] === "bun" || s[0] === "node") && /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(s[1] ?? ""));
  const headRanZero = headCounts.hasTestRunner && (isDirectScript ? (headCounts.matched && (headCounts.passed <= 0 || headCounts.failed > 0)) : (!headCounts.matched || headCounts.passed <= 0 || headCounts.failed > 0));
  const baseInvalidRed = Boolean(baseRun.signal === "SIGTERM" || baseRun.error || INVALID_RED_ERROR.test(baseOut) || /\b(?:ModuleNotFoundError|cannot find package)\b/i.test(baseOut));
  const passed = baseCode !== 0 && !baseInvalidRed && headCode === 0 && !headRanZero;
  const reason = passed
    ? `Verified Red-Before-Fix: tests failed behaviorally on ${baseRef} (exit ${baseCode}) and passed on working tree (exit 0).`
    : baseInvalidRed
      ? `INVALID RED: base run on ${baseRef} failed due to timeout or compile/import error rather than a behavioral assertion failure.`
      : baseCode === 0
        ? `THEATER TEST DETECTED: test command already passed on unfixed ${baseRef} (exit 0)!`
        : headRanZero
          ? "INVALID HEAD RUN: test runner exited 0 on working tree without executing > 0 passing tests."
          : `Test command still fails on working tree (exit ${headCode}).`;
  return { passed, baseRef, copiedTestFiles, baseExitCode: baseCode, headExitCode: headCode, reason };
}

export function runRedBeforeFix(repoPath: string, baseRef: string, testCmd: string): RedBeforeFixResult {
  if (!baseRef || baseRef.startsWith("-")) throw new Error(`Invalid git baseRef "${baseRef}".`);
  const root = path.resolve(repoPath);
  const copiedTestFiles = collectChangedTestFiles(root, baseRef);
  if (copiedTestFiles.length === 0) {
    return { passed: false, baseRef, copiedTestFiles: [], baseExitCode: -1, headExitCode: -1, reason: "No modified or added test files found to prove red-before-fix." };
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rbf-"));
  const worktreeDir = path.join(tmpDir, "base");
  try {
    const addWt = runGitClean(root, ["worktree", "add", "--detach", worktreeDir, baseRef]);
    if (addWt.status !== 0) {
      return { passed: false, baseRef, copiedTestFiles, baseExitCode: -1, headExitCode: -1, reason: `Failed to create base worktree at ${baseRef}: ${(addWt.stderr ?? "").trim()}` };
    }
    const resolvedWorktree = path.resolve(worktreeDir);
    for (const rel of copiedTestFiles) {
      const dest = path.resolve(resolvedWorktree, rel);
      if (!dest.startsWith(`${resolvedWorktree}${path.sep}`)) throw new Error(`Refusing to copy test file outside worktree: ${rel}`);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.join(root, rel), dest);
    }
    const parsedCmd = parseAndValidateCommandArgv("canary", testCmd, root);
    if (parsedCmd.error) {
      return { passed: false, baseRef, copiedTestFiles, baseExitCode: -1, headExitCode: -1, reason: `Unsafe red-before-fix test command rejected: ${parsedCmd.error}` };
    }
    const srcNm = path.join(root, "node_modules");
    const wtNm = path.join(resolvedWorktree, "node_modules");
    if (fs.existsSync(srcNm) && !fs.existsSync(wtNm)) { try { fs.symlinkSync(srcNm, wtNm); } catch { void 0; } }
    const cleanEnv = scrubChildEnv();
    const baseTmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rbf-b-"));
    const headTmp = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rbf-h-"));
    try {
      const mkEnv = (t: string): NodeJS.ProcessEnv => ({ ...cleanEnv, HOME: t, XDG_CONFIG_HOME: t, TMPDIR: t, TMP: t, TEMP: t });
      const baseRun = runArgvChain(parsedCmd.steps, { cwd: worktreeDir, env: mkEnv(baseTmp), timeoutMs: 120_000, stepCwds: parsedCmd.stepCwds });
      const headRun = runArgvChain(parsedCmd.steps, { cwd: root, env: mkEnv(headTmp), timeoutMs: 120_000, stepCwds: parsedCmd.stepCwds });
      return summarizeRedBeforeFixRuns({ baseRun, headRun, steps: parsedCmd.steps, baseRef, copiedTestFiles });
    } finally {
      fs.rmSync(baseTmp, { recursive: true, force: true });
      fs.rmSync(headTmp, { recursive: true, force: true });
    }
  } finally {
    runGitClean(root, ["worktree", "remove", "--force", worktreeDir]);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
