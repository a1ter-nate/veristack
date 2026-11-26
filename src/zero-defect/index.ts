import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DiscoveredRepo } from "../discover.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "../rungs/command-audit.ts";
import type { Finding, RungId } from "../types.ts";
import { auditFormalSync } from "./formal-sync.ts";
import { auditLaws } from "./laws.ts";
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

export function auditZeroDefectArtifacts(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  const allPathSet = new Set(repo.allRelPaths);
  const testText = repo.files
    .filter((f) => f.isTest)
    .map((f) => f.content)
    .join("\n");

  const planFile = repo.files.find(
    (f) => f.rel === ".verification/control-plan.json" || f.rel === "control-plan.json",
  );
  if (planFile) {
    try {
      const parsed: unknown = JSON.parse(planFile.content);
      const entries = isRecord(parsed) && Array.isArray(parsed.controls) ? parsed.controls : [];
      for (const raw of entries) {
        if (!isRecord(raw)) continue;
        const id = typeof raw.id === "string" ? raw.id : "unknown";
        const severity = typeof raw.severity === "number" ? raw.severity : 0;
        const maxRung = typeof raw.maxAllowedRung === "string" ? (raw.maxAllowedRung as RungId) : "R8";
        const controlRef = typeof raw.controlRef === "string" ? raw.controlRef : "";
        const reqId = typeof raw.reqId === "string" ? raw.reqId : undefined;

        if (severity >= 8 && (RUNG_ORDER[maxRung] ?? 8) > RUNG_ORDER.R4) {
          findings.push({
            id: `ZD:fmea-rung:${id}`,
            rule: "fmea-high-severity-rung",
            category: "oracle-lock",
            rung: "R1",
            severity: "error",
            file: planFile.rel,
            line: 1,
            message: `Control Plan entry '${id}' has severity ${severity} (>= 8) but allows detection at ${maxRung} (> R4).`,
            fix: "Push high-severity controls down to R0–R4 (type, lint, table, MBT, or real-engine test).",
          });
        }

        const refPath = controlRef.split("#")[0]?.trim() ?? "";
        if (!refPath || !allPathSet.has(refPath)) {
          findings.push({
            id: `ZD:fmea-orphan:${id}`,
            rule: "fmea-orphaned-control",
            category: "oracle-lock",
            rung: "R1",
            severity: "error",
            file: planFile.rel,
            line: 1,
            message: `Control Plan entry '${id}' references missing control artifact '${controlRef}'.`,
            fix: "Restore the missing verification control or update the Control Plan with a live replacement.",
          });
        }

        if (reqId && !testText.includes(reqId)) {
          findings.push({
            id: `ZD:req-untraced:${reqId}`,
            rule: "traceability-unverified-requirement",
            category: "oracle-lock",
            rung: "R1",
            severity: "error",
            file: planFile.rel,
            line: 1,
            message: `Requirement '${reqId}' in Control Plan '${id}' has no linked test tag or fixture reference.`,
            fix: `Tag at least one executable test with '${reqId}' to maintain bidirectional traceability.`,
          });
        }
      }
    } catch {
      findings.push({
        id: `ZD:fmea-json:${planFile.rel}`,
        rule: "fmea-invalid-json",
        category: "oracle-lock",
        rung: "R1",
        severity: "error",
        file: planFile.rel,
        line: 1,
        message: `${planFile.rel} is not valid JSON.`,
        fix: "Fix JSON syntax in the FMEA Control Plan.",
      });
    }
  }

  const escapeFile = repo.files.find(
    (f) => f.rel === ".verification/escapes.json" || f.rel === "escapes.json",
  );
  if (escapeFile) {
    try {
      const parsed: unknown = JSON.parse(escapeFile.content);
      const records = isRecord(parsed) && Array.isArray(parsed.escapes) ? parsed.escapes : [];
      const byClass = new Map<string, Array<{ id: string; pokaYokeRef: string }>>();
      for (const raw of records) {
        if (!isRecord(raw) || typeof raw.defectClass !== "string") continue;
        const list = byClass.get(raw.defectClass) ?? [];
        list.push({
          id: typeof raw.id === "string" ? raw.id : "?",
          pokaYokeRef: typeof raw.pokaYokeRef === "string" ? raw.pokaYokeRef.trim() : "",
        });
        byClass.set(raw.defectClass, list);
      }

      for (const [defectClass, list] of byClass.entries()) {
        if (list.length < 2) continue;
        const hasValidPokaYoke = list.some((entry) => {
          const refPath = entry.pokaYokeRef.split("#")[0]?.trim() ?? "";
          return refPath.length > 0 && allPathSet.has(refPath);
        });
        if (!hasValidPokaYoke) {
          findings.push({
            id: `ZD:a3-repeat:${defectClass}`,
            rule: "a3-repeat-defect-no-poka-yoke",
            category: "oracle-lock",
            rung: "R1",
            severity: "error",
            file: escapeFile.rel,
            line: 1,
            message: `Escaped defect class '${defectClass}' occurred ${list.length} times without an R0/R1 Poka-Yoke lint/type check in pokaYokeRef.`,
            fix: "Add a deterministic R0/R1 compiler/lint check for this defect class and link its file path in pokaYokeRef.",
          });
        }
      }
    } catch {
      findings.push({
        id: `ZD:escape-json:${escapeFile.rel}`,
        rule: "a3-invalid-json",
        category: "oracle-lock",
        rung: "R1",
        severity: "error",
        file: escapeFile.rel,
        line: 1,
        message: `${escapeFile.rel} is not valid JSON.`,
        fix: "Fix JSON syntax in the A3 escape ledger.",
      });
    }
  }

  findings.push(...auditFormalSync(repo));
  findings.push(...auditLaws(repo).findings);
  return findings;
}

export function evaluateSpcSeries(metric: string, values: readonly number[], upperSpecLimit: number): SpcResult {
  const invalidFail = (reason: string): SpcResult => ({
    metric,
    count: Array.isArray(values) ? values.length : 0,
    mean: 0,
    stdDev: 0,
    upperSpecLimit,
    cpk: null,
    nelsonRule2Breach: false,
    nelsonRule3Breach: false,
    cpkBreach: false,
    status: "spec_breach",
    reasons: [reason],
  });
  if (!Number.isFinite(upperSpecLimit)) {
    return invalidFail(`Invalid upperSpecLimit (${String(upperSpecLimit)}); must be a finite number.`);
  }
  if (!Array.isArray(values) || values.length < 3) {
    return invalidFail(`SPC requires at least 3 finite observations (received ${Array.isArray(values) ? values.length : 0}).`);
  }
  if (values.some((v) => typeof v !== "number" || !Number.isFinite(v))) {
    return invalidFail("SPC series contains non-numeric or non-finite values.");
  }

  const mean = values.reduce((acc, v) => acc + v, 0) / values.length;
  const variance = values.reduce((acc, v) => acc + (v - mean) ** 2, 0) / (values.length - 1);
  const stdDev = Math.sqrt(variance);
  const cpk = stdDev > 0 ? Number(((upperSpecLimit - mean) / (3 * stdDev)).toFixed(3)) : null;

  let consecAbove = 0;
  let nelsonRule2Breach = false;
  let consecRising = 1;
  let nelsonRule3Breach = false;
  let nelsonRule1Outlier = false;

  for (let i = 0; i < values.length; i++) {
    const cur = values[i] ?? 0;
    if (stdDev > 0 && cur > mean + 3 * stdDev) nelsonRule1Outlier = true;
    if (!nelsonRule1Outlier && values.length >= 4) {
      const others = values.filter((_, idx) => idx !== i);
      const oMean = others.reduce((acc, v) => acc + v, 0) / others.length;
      const oVar = others.reduce((acc, v) => acc + (v - oMean) ** 2, 0) / Math.max(1, others.length - 1);
      const oSd = Math.sqrt(oVar);
      if ((oSd > 0 && cur > oMean + 3 * oSd) || (oSd === 0 && Math.abs(cur - oMean) > Math.max(1, Math.abs(oMean) * 0.5))) {
        nelsonRule1Outlier = true;
      }
    }
    if (cur > mean) {
      consecAbove += 1;
      if (consecAbove >= 7) nelsonRule2Breach = true;
    } else {
      consecAbove = 0;
    }
    if (i > 0 && cur > (values[i - 1] ?? 0)) {
      consecRising += 1;
      if (consecRising >= 6) nelsonRule3Breach = true;
    } else if (i > 0) {
      consecRising = 1;
    }
  }

  const latest = values[values.length - 1] ?? 0;
  const cpkBreach = cpk !== null && cpk < 1.33;
  const reasons: string[] = [];
  if (latest > upperSpecLimit) reasons.push(`Latest value ${latest} exceeds USL ${upperSpecLimit}.`);
  if (nelsonRule1Outlier) reasons.push("Nelson Rule 1: observation exceeds mean + 3*sigma control limit.");
  if (nelsonRule2Breach) reasons.push("Nelson Rule 2: >= 7 consecutive points above historical mean.");
  if (nelsonRule3Breach) reasons.push("Nelson Rule 3: >= 6 consecutive monotonically worsening points.");
  if (cpkBreach && cpk !== null) reasons.push(`Process capability Cpk=${cpk} dropped below 1.33 headroom floor.`);

  const status: SpcResult["status"] =
    latest > upperSpecLimit ? "spec_breach" : reasons.length > 0 ? "drift_warning" : "in_control";

  return {
    metric,
    count: values.length,
    mean: Number(mean.toFixed(4)),
    stdDev: Number(stdDev.toFixed(4)),
    upperSpecLimit,
    cpk,
    nelsonRule2Breach,
    nelsonRule3Breach,
    cpkBreach,
    status,
    reasons,
  };
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
  /\b(?:SyntaxError|ReferenceError|Cannot\s+find\s+module|TS\d{4}:|error\[E\d{4}\]|IndentationError|ImportError)\b/;

export { runTwoSidedOracleCheck, type TwoSidedOracleResult } from "../rungs/oracle-check.ts";

export function runRedBeforeFix(repoPath: string, baseRef: string, testCmd: string): RedBeforeFixResult {
  if (!baseRef || baseRef.startsWith("-")) {
    throw new Error(`Invalid git baseRef "${baseRef}".`);
  }
  const root = path.resolve(repoPath);
  const changed = spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" });
  const diffNames = spawnSync("git", ["diff", "--name-only", baseRef, "--"], { cwd: root, encoding: "utf8" });

  const candidates = new Set<string>();
  for (const line of `${changed.stdout ?? ""}\n${diffNames.stdout ?? ""}`.split(/\r?\n/)) {
    const cleaned = line.replace(/^[ MADRCU?!]{1,2}\s+/, "").trim();
    if (!cleaned) continue;
    if (/(?:^|\/)(?:tests?|__tests__|spec)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.(?:py|rs|go)$|Tests?\.cs$/i.test(cleaned)) {
      candidates.add(cleaned);
    }
  }

  const copiedTestFiles = [...candidates].filter((rel) => fs.existsSync(path.join(root, rel)));
  if (copiedTestFiles.length === 0) {
    return {
      passed: false,
      baseRef,
      copiedTestFiles: [],
      baseExitCode: -1,
      headExitCode: -1,
      reason: "No modified or added test files found to prove red-before-fix.",
    };
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-rbf-"));
  const worktreeDir = path.join(tmpDir, "base");
  try {
    const addWt = spawnSync("git", ["worktree", "add", "--detach", worktreeDir, baseRef], {
      cwd: root,
      encoding: "utf8",
    });
    if (addWt.status !== 0) {
      return {
        passed: false,
        baseRef,
        copiedTestFiles,
        baseExitCode: -1,
        headExitCode: -1,
        reason: `Failed to create base worktree at ${baseRef}: ${(addWt.stderr ?? "").trim()}`,
      };
    }

    const resolvedWorktree = path.resolve(worktreeDir);
    for (const rel of copiedTestFiles) {
      const dest = path.resolve(resolvedWorktree, rel);
      if (!dest.startsWith(`${resolvedWorktree}${path.sep}`)) {
        throw new Error(`Refusing to copy test file outside worktree: ${rel}`);
      }
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.join(root, rel), dest);
    }

    const parsedCmd = parseAndValidateCommandArgv("canary", testCmd, root);
    if (parsedCmd.error) {
      return {
        passed: false,
        baseRef,
        copiedTestFiles,
        baseExitCode: -1,
        headExitCode: -1,
        reason: `Unsafe red-before-fix test command rejected: ${parsedCmd.error}`,
      };
    }
    const cleanEnv = scrubChildEnv();
    const baseRun = runArgvChain(parsedCmd.steps, worktreeDir, cleanEnv, 120_000);
    const headRun = runArgvChain(parsedCmd.steps, root, cleanEnv, 120_000);
    const baseCode = baseRun.status ?? 1;
    const headCode = headRun.status ?? 1;
    const baseOut = `${baseRun.stdout ?? ""}\n${baseRun.stderr ?? ""}`;
    const baseInvalidRed = Boolean(baseRun.signal === "SIGTERM" || baseRun.error || INVALID_RED_ERROR.test(baseOut));
    const passed = baseCode !== 0 && !baseInvalidRed && headCode === 0;

    return {
      passed,
      baseRef,
      copiedTestFiles,
      baseExitCode: baseCode,
      headExitCode: headCode,
      reason: passed
        ? `Verified Red-Before-Fix: tests failed behaviorally on ${baseRef} (exit ${baseCode}) and passed on working tree (exit 0).`
        : baseInvalidRed
          ? `INVALID RED: base run on ${baseRef} failed due to timeout or compile/import error rather than a behavioral assertion failure.`
          : baseCode === 0
            ? `THEATER TEST DETECTED: test command already passed on unfixed ${baseRef} (exit 0)!`
            : `Test command still fails on working tree (exit ${headCode}).`,
    };
  } finally {
    spawnSync("git", ["worktree", "remove", "--force", worktreeDir], { cwd: root, encoding: "utf8" });
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
