import fs from "node:fs";
import path from "node:path";
import type { Finding, RungCoverageGrade, RungStatus } from "./types.ts";

export interface RatchetRungEntry {
  grade: RungCoverageGrade;
  score: number;
  executedInCi: boolean;
}

export interface RatchetBaseline {
  version: 1;
  rules: Record<string, number>;
  rungs?: Record<string, RatchetRungEntry>;
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
): RatchetBaseline {
  const counts = new Map<string, number>();
  for (const f of findings) {
    if (f.severity === "info") continue;
    counts.set(f.rule, (counts.get(f.rule) ?? 0) + 1);
  }
  const rules: Record<string, number> = {};
  for (const key of [...counts.keys()].sort()) {
    rules[key] = counts.get(key) ?? 0;
  }
  if (!rungs || rungs.length === 0) {
    return { version: 1, rules };
  }
  const rungMap: Record<string, RatchetRungEntry> = {};
  for (const r of rungs) {
    rungMap[r.rung] = {
      grade: r.coverageGrade,
      score: r.coverageScore,
      executedInCi: r.executedInCi,
    };
  }
  return { version: 1, rules, rungs: rungMap };
}

export function evaluateRatchet(
  findings: readonly Finding[],
  baseline: RatchetBaseline,
  rungs?: readonly RungStatus[],
): RatchetEvaluation {
  const current = buildRatchetBaseline(findings).rules;
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

  const rungRegressions: RatchetRungRegression[] = [];
  const hasRungBaseline = Boolean(baseline.rungs && Object.keys(baseline.rungs).length > 0);
  if (baseline.rungs && rungs) {
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
      } else if (base.executedInCi && !r.executedInCi && r.coverageGrade !== "not-applicable") {
        rungRegressions.push({
          rung: r.rung,
          reason: "stopped executing in CI workflows",
        });
      }
    }
  }

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
