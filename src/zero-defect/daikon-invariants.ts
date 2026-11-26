import fs from "node:fs";
import path from "node:path";
import type { Finding } from "../types.ts";

export interface TraceSample {
  fn: string;
  args?: Record<string, unknown>;
  result?: unknown;
  throws?: boolean;
}

export interface InferredInvariant {
  fn: string;
  kind:
    | "never-throws"
    | "non-null-result"
    | "result-type"
    | "non-negative-result"
    | "positive-result"
    | "relational-le-arg"
    | "relational-ge-arg"
    | "length-le-arg-length"
    | "enum-domain"
    | "non-empty-result"
    | "sorted-numeric-array";
  detail: string;
  values?: string[];
}

export interface InvariantSnapshot {
  schemaVersion: 1;
  sampleCounts: Record<string, number>;
  invariants: InferredInvariant[];
}

export interface InvariantDiffReport {
  passed: boolean;
  totalBaseline: number;
  totalCurrent: number;
  violations: Finding[];
  newInvariants: InferredInvariant[];
}

function runtimeType(val: unknown): string {
  if (val === null) return "null";
  if (Array.isArray(val)) return "array";
  return typeof val;
}

function isSortedNumeric(val: unknown): boolean {
  if (!Array.isArray(val) || val.length < 2) return false;
  for (let i = 0; i < val.length; i++) {
    if (typeof val[i] !== "number" || !Number.isFinite(val[i])) return false;
    if (i > 0 && (val[i] as number) < (val[i - 1] as number)) return false;
  }
  return true;
}

export function inferDynamicInvariants(samples: readonly TraceSample[]): InvariantSnapshot {
  const byFn = new Map<string, TraceSample[]>();
  for (const s of samples) {
    if (!s || typeof s.fn !== "string" || !s.fn.trim()) continue;
    const arr = byFn.get(s.fn) ?? [];
    arr.push(s);
    byFn.set(s.fn, arr);
  }

  const sampleCounts: Record<string, number> = {};
  const invariants: InferredInvariant[] = [];

  for (const fn of [...byFn.keys()].sort()) {
    const group = byFn.get(fn) ?? [];
    sampleCounts[fn] = group.length;
    if (group.length < 3) continue;

    if (group.every((s) => s.throws !== true)) {
      invariants.push({ fn, kind: "never-throws", detail: `${fn} never throws` });
    }

    const okSamples = group.filter((s) => s.throws !== true);
    if (okSamples.length < 3) continue;

    if (okSamples.every((s) => s.result !== null && s.result !== undefined)) {
      invariants.push({ fn, kind: "non-null-result", detail: `${fn} result is always non-null` });
    }

    const types = new Set(okSamples.map((s) => runtimeType(s.result)));
    if (types.size === 1) {
      const onlyType = [...types][0] ?? "unknown";
      invariants.push({ fn, kind: "result-type", detail: onlyType });

      if (onlyType === "number") {
        const nums = okSamples.map((s) => s.result as number);
        if (nums.every((n) => Number.isFinite(n) && n >= 0)) {
          invariants.push({ fn, kind: "non-negative-result", detail: "result >= 0" });
        }
        if (nums.every((n) => Number.isFinite(n) && n > 0)) {
          invariants.push({ fn, kind: "positive-result", detail: "result > 0" });
        }

        const argKeys = new Set<string>();
        for (const s of okSamples) {
          for (const [k, v] of Object.entries(s.args ?? {})) {
            if (typeof v === "number" && Number.isFinite(v)) argKeys.add(k);
          }
        }
        for (const key of [...argKeys].sort()) {
          const pairs = okSamples
            .map((s) => ({ res: s.result as number, arg: s.args?.[key] }))
            .filter((p): p is { res: number; arg: number } => typeof p.arg === "number" && Number.isFinite(p.arg));
          if (pairs.length < 3) continue;
          if (pairs.every((p) => p.res <= p.arg)) {
            invariants.push({ fn, kind: "relational-le-arg", detail: key });
          }
          if (pairs.every((p) => p.res >= p.arg)) {
            invariants.push({ fn, kind: "relational-ge-arg", detail: key });
          }
        }
      }

      if (onlyType === "string") {
        const strs = okSamples.map((s) => s.result as string);
        if (strs.every((s) => s.length > 0)) {
          invariants.push({ fn, kind: "non-empty-result", detail: "result.length > 0" });
        }
        const distinct = [...new Set(strs)].sort();
        if (okSamples.length >= 4 && distinct.length <= 6 && distinct.length < okSamples.length) {
          invariants.push({ fn, kind: "enum-domain", detail: distinct.join("|"), values: distinct });
        }
      }

      if (onlyType === "array") {
        const arrs = okSamples.map((s) => s.result as unknown[]);
        if (arrs.every((a) => a.length > 0)) {
          invariants.push({ fn, kind: "non-empty-result", detail: "result.length > 0" });
        }
        if (arrs.filter((a) => a.length >= 2).length >= 2 && arrs.every((a) => a.length < 2 || isSortedNumeric(a))) {
          invariants.push({ fn, kind: "sorted-numeric-array", detail: "non-decreasing numeric array" });
        }

        const argKeys = new Set<string>();
        for (const s of okSamples) {
          for (const [k, v] of Object.entries(s.args ?? {})) {
            if (Array.isArray(v) || typeof v === "string") argKeys.add(k);
          }
        }
        for (const key of [...argKeys].sort()) {
          const pairs = okSamples
            .map((s) => ({ resLen: (s.result as unknown[]).length, arg: s.args?.[key] }))
            .filter(
              (p): p is { resLen: number; arg: string | unknown[] } =>
                Array.isArray(p.arg) || typeof p.arg === "string",
            );
          if (pairs.length >= 3 && pairs.every((p) => p.resLen <= p.arg.length)) {
            invariants.push({ fn, kind: "length-le-arg-length", detail: key });
          }
        }
      }
    }
  }

  return { schemaVersion: 1, sampleCounts, invariants };
}

function invariantKey(inv: InferredInvariant): string {
  return `${inv.fn}::${inv.kind}::${inv.kind === "enum-domain" ? "domain" : inv.detail}`;
}

export function compareInvariantSnapshots(
  baseline: InvariantSnapshot,
  current: InvariantSnapshot,
  baselineFile = ".verification/invariants.json",
): InvariantDiffReport {
  const curMap = new Map<string, InferredInvariant>();
  for (const inv of current.invariants) curMap.set(invariantKey(inv), inv);

  const baseMap = new Map<string, InferredInvariant>();
  for (const inv of baseline.invariants) baseMap.set(invariantKey(inv), inv);

  const violations: Finding[] = [];
  if (baseline.invariants.length === 0) {
    violations.push({
      id: `DAIKON:empty-baseline:${baselineFile}`,
      rule: "daikon-empty-baseline",
      category: "oracle-lock",
      rung: "R3",
      severity: "error",
      file: baselineFile,
      line: 1,
      message: `Invariant baseline '${baselineFile}' contains 0 invariants — failing closed.`,
      fix: "Generate a non-empty invariant baseline from real execution traces.",
    });
  }
  const missingFns = new Set<string>();
  for (const baseInv of baseline.invariants) {
    const curCount = current.sampleCounts[baseInv.fn] ?? 0;
    if (curCount < 3) {
      if (!missingFns.has(baseInv.fn)) {
        missingFns.add(baseInv.fn);
        violations.push({
          id: `DAIKON:unobserved:${baseInv.fn}`,
          rule: "daikon-invariant-unobserved",
          category: "oracle-lock",
          rung: "R3",
          severity: "error",
          file: baselineFile,
          line: 1,
          message: `Baseline function '${baseInv.fn}' has only ${curCount} trace sample(s) in current run (< 3 required) — failing closed.`,
          fix: `Record at least 3 execution traces for '${baseInv.fn}' so locked dynamic invariants are actually checked.`,
        });
      }
      continue;
    }
    const key = invariantKey(baseInv);
    const curInv = curMap.get(key);
    let broken = !curInv;
    let extraDetail = "";
    if (!broken && baseInv.kind === "enum-domain" && curInv && baseInv.values && curInv.values) {
      const allowed = new Set(baseInv.values);
      const unexpected = curInv.values.filter((v) => !allowed.has(v));
      if (unexpected.length > 0) {
        broken = true;
        extraDetail = ` (unexpected value(s): ${unexpected.join(", ")})`;
      }
    }
    if (broken) {
      violations.push({
        id: `DAIKON:${baseInv.fn}:${baseInv.kind}:${baseInv.detail}`,
        rule: "daikon-invariant-violated",
        category: "oracle-lock",
        rung: "R3",
        severity: "error",
        file: baselineFile,
        line: 1,
        message: `Dynamic invariant '${baseInv.kind}' (${baseInv.detail}) for '${baseInv.fn}' was violated in current execution traces${extraDetail}.`,
        fix: `Fix the behavioral regression in '${baseInv.fn}' or intentionally update ${baselineFile} via human review (--update).`,
      });
    }
  }

  const newInvariants = current.invariants.filter((inv) => !baseMap.has(invariantKey(inv)));

  return {
    passed: violations.length === 0,
    totalBaseline: baseline.invariants.length,
    totalCurrent: current.invariants.length,
    violations,
    newInvariants,
  };
}

export function writeInvariantSnapshot(filePath: string, snapshot: InvariantSnapshot): void {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
}

export function formatInvariantDiffReport(snapshot: InvariantSnapshot, diff?: InvariantDiffReport): string {
  const lines = [
    `Dynamic Invariants: ${snapshot.invariants.length} inferred across ${Object.keys(snapshot.sampleCounts).length} function(s)`,
  ];
  if (!diff) {
    for (const inv of snapshot.invariants.slice(0, 30)) {
      lines.push(`  - ${inv.fn}: [${inv.kind}] ${inv.detail}`);
    }
    return lines.join("\n");
  }
  lines.push(
    `Comparison [${diff.passed ? "PASS" : "FAIL"}]: baseline=${diff.totalBaseline} current=${diff.totalCurrent} violations=${diff.violations.length} new=${diff.newInvariants.length}`,
  );
  for (const v of diff.violations) {
    lines.push(`  - [VIOLATION] ${v.message}`);
    lines.push(`      Fix: ${v.fix}`);
  }
  for (const n of diff.newInvariants.slice(0, 10)) {
    lines.push(`  + [NEW] ${n.fn}: [${n.kind}] ${n.detail}`);
  }
  return lines.join("\n");
}
