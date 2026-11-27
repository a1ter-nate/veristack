import fs from "node:fs";
import path from "node:path";
import type { Finding, RungCoverageGrade, RungStatus } from "@veristack/plugin";

export interface RatchetRungEntry {
  grade: RungCoverageGrade;
  score: number;
  executedInCi: boolean;
}

export interface RatchetBaseline {
  version: 1;
  rules: Record<string, number>;
  ruleFiles?: Record<string, number>;
  rungs?: Record<string, RatchetRungEntry>;
  dependenciesCount?: number;
}

export interface RatchetDelta {
  rule: string;
  baseline: number;
  current: number;
  delta: number;
}

export interface RatchetRungRegression {
  rung: string;
  reason: string;
}

export interface RatchetEvaluation {
  passed: boolean;
  hasRungBaseline: boolean;
  regressions: RatchetDelta[];
  tightenAvailable: RatchetDelta[];
  rungRegressions: RatchetRungRegression[];
  currentCounts: Record<string, number>;
}

const GRADE_RANK: Record<RungCoverageGrade, number> = {
  "not-covered": 0,
  "over-budget": 1,
  "poorly-covered": 2,
  "well-covered": 3,
  "not-applicable": -1,
};

export function buildRatchetBaseline(
  findings: readonly Finding[],
  rungs?: readonly RungStatus[],
  dependenciesCount?: number,
): RatchetBaseline {
  const counts = new Map<string, number>();
  const fileCounts = new Map<string, number>();
  for (const f of findings) {
    if (f.severity === "info") continue;
    counts.set(f.rule, (counts.get(f.rule) ?? 0) + 1);
    const rfKey = `${f.rule}::${f.file}`;
    fileCounts.set(rfKey, (fileCounts.get(rfKey) ?? 0) + 1);
  }
  const rules: Record<string, number> = {};
  for (const key of [...counts.keys()].sort()) {
    rules[key] = counts.get(key) ?? 0;
  }
  const ruleFiles: Record<string, number> = {};
  for (const key of [...fileCounts.keys()].sort()) {
    ruleFiles[key] = fileCounts.get(key) ?? 0;
  }
  const depPart = typeof dependenciesCount === "number" ? { dependenciesCount } : {};
  if (!rungs || rungs.length === 0) {
    return { version: 1, rules, ruleFiles, ...depPart };
  }
  const rungMap: Record<string, RatchetRungEntry> = {};
  for (const r of rungs) {
    rungMap[r.rung] = {
      grade: r.coverageGrade,
      score: r.coverageScore,
      executedInCi: r.executedInCi,
    };
  }
  return { version: 1, rules, ruleFiles, rungs: rungMap, ...depPart };
}

function evaluateRungRegressions(
  baseline: RatchetBaseline,
  rungs?: readonly RungStatus[],
): { hasRungBaseline: boolean; rungRegressions: RatchetRungRegression[] } {
  const rungRegressions: RatchetRungRegression[] = [];
  const hasRungBaseline = Boolean(baseline.rungs && Object.keys(baseline.rungs).length > 0);
  if (rungs && rungs.length > 0 && !hasRungBaseline) {
    rungRegressions.push({
      rung: "ALL",
      reason: "ratchet baseline is missing 'rungs' snapshot — refusing to hide rung regressions",
    });
    return { hasRungBaseline, rungRegressions };
  }
  if (!baseline.rungs || !rungs) return { hasRungBaseline, rungRegressions };
  for (const r of rungs) {
    const base = baseline.rungs[r.rung];
    if (!base) continue;
    if (base.grade !== "not-applicable" && r.coverageGrade === "not-applicable") {
      rungRegressions.push({
        rung: r.rung,
        reason: `archetype downgrade excused rung ${base.grade} -> not-applicable`,
      });
    } else if (
      base.grade !== "not-applicable" &&
      r.coverageGrade !== "not-applicable" &&
      GRADE_RANK[r.coverageGrade] < GRADE_RANK[base.grade]
    ) {
      rungRegressions.push({
        rung: r.rung,
        reason: `grade regressed ${base.grade} -> ${r.coverageGrade} (${base.score}% -> ${r.coverageScore}%)`,
      });
    } else if (
      base.grade !== "not-applicable" &&
      r.coverageGrade !== "not-applicable" &&
      r.coverageScore < base.score
    ) {
      rungRegressions.push({
        rung: r.rung,
        reason: `score regressed ${base.score}% -> ${r.coverageScore}%`,
      });
    } else if (base.executedInCi && !r.executedInCi && r.coverageGrade !== "not-applicable") {
      rungRegressions.push({
        rung: r.rung,
        reason: "stopped executing in CI workflows",
      });
    }
  }
  return { hasRungBaseline, rungRegressions };
}

function evaluateDependencyDelta(
  baselineDeps: number | undefined,
  currentDeps: number | undefined,
  regressions: RatchetDelta[],
  tightenAvailable: RatchetDelta[],
): void {
  if (typeof baselineDeps !== "number" || typeof currentDeps !== "number") return;
  if (currentDeps > baselineDeps) {
    regressions.push({ rule: "tiger-minimal-dependencies", baseline: baselineDeps, current: currentDeps, delta: currentDeps - baselineDeps });
  } else if (currentDeps < baselineDeps) {
    tightenAvailable.push({ rule: "tiger-minimal-dependencies", baseline: baselineDeps, current: currentDeps, delta: currentDeps - baselineDeps });
  }
}

export function evaluateRatchet(
  findings: readonly Finding[],
  baseline: RatchetBaseline,
  rungs?: readonly RungStatus[],
  currentDependenciesCount?: number,
): RatchetEvaluation {
  if (!baseline) throw new Error("Ratchet baseline is required.");
  if (!baseline.rules) throw new Error("Ratchet baseline rules are required.");
  const built = buildRatchetBaseline(findings);
  const current = built.rules;
  const allRules = new Set([...Object.keys(baseline.rules), ...Object.keys(current)]);
  const regressions: RatchetDelta[] = [];
  const tightenAvailable: RatchetDelta[] = [];

  for (const rule of [...allRules].sort()) {
    const baseVal = baseline.rules[rule] ?? 0;
    const curVal = current[rule] ?? 0;
    if (curVal > baseVal) {
      regressions.push({ rule, baseline: baseVal, current: curVal, delta: curVal - baseVal });
    } else if (curVal < baseVal) {
      tightenAvailable.push({ rule, baseline: baseVal, current: curVal, delta: curVal - baseVal });
    }
  }

  const regressedRules = new Set(regressions.map((r) => r.rule));
  if (baseline.ruleFiles && built.ruleFiles) {
    for (const [rfKey, curVal] of Object.entries(built.ruleFiles)) {
      const ruleName = rfKey.split("::")[0] ?? rfKey;
      if (regressedRules.has(ruleName)) continue;
      const baseVal = baseline.ruleFiles[rfKey] ?? 0;
      if (curVal > baseVal) {
        regressions.push({ rule: rfKey, baseline: baseVal, current: curVal, delta: curVal - baseVal });
      }
    }
  }

  const { hasRungBaseline, rungRegressions } = evaluateRungRegressions(baseline, rungs);
  evaluateDependencyDelta(baseline.dependenciesCount, currentDependenciesCount, regressions, tightenAvailable);

  return {
    passed: regressions.length === 0 && tightenAvailable.length === 0 && rungRegressions.length === 0,
    hasRungBaseline,
    regressions,
    tightenAvailable,
    rungRegressions,
    currentCounts: current,
  };
}

export function writeRatchetBaseline(filePath: string, baseline: RatchetBaseline): void {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
}
