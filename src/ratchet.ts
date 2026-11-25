import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.ts";

export interface RatchetBaseline {
  version: 1;
  rules: Record<string, number>;
}

export interface RatchetDelta {
  rule: string;
  baseline: number;
  current: number;
  delta: number;
}

export interface RatchetEvaluation {
  passed: boolean;
  regressions: RatchetDelta[];
  tightenAvailable: RatchetDelta[];
  currentCounts: Record<string, number>;
}

export function buildRatchetBaseline(findings: readonly Finding[]): RatchetBaseline {
  const counts = new Map<string, number>();
  for (const f of findings) {
    if (f.severity === "info") continue;
    counts.set(f.rule, (counts.get(f.rule) ?? 0) + 1);
  }
  const rules: Record<string, number> = {};
  for (const key of [...counts.keys()].sort()) {
    rules[key] = counts.get(key) ?? 0;
  }
  return { version: 1, rules };
}

export function evaluateRatchet(
  findings: readonly Finding[],
  baseline: RatchetBaseline,
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

  return {
    passed: regressions.length === 0 && tightenAvailable.length === 0,
    regressions,
    tightenAvailable,
    currentCounts: current,
  };
}

export function writeRatchetBaseline(filePath: string, baseline: RatchetBaseline): void {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
}
