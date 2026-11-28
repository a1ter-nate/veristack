import fs from "node:fs";
import path from "node:path";
import type { Finding } from "@veristack/plugin";

export interface TemporalTraceSequence {
  traceId: string;
  events: readonly string[];
}

export interface TemporalProtocolRule {
  kind: "always-precedes" | "always-pairs";
  first: string;
  second: string;
  support: number;
}

export interface TemporalProtocolSnapshot {
  schemaVersion: 1;
  traceCount: number;
  rules: TemporalProtocolRule[];
}

export interface TemporalProtocolDiff {
  passed: boolean;
  violations: Finding[];
  newRules: TemporalProtocolRule[];
}

function evaluateTemporalPair(
  clean: readonly TemporalTraceSequence[],
  a: string,
  b: string,
  rules: TemporalProtocolRule[],
): void {
  let bTraces = 0;
  let aPrecededB = 0;
  let aTraces = 0;
  let aFollowedByB = 0;
  for (const t of clean) {
    const firstA = t.events.indexOf(a);
    const firstB = t.events.indexOf(b);
    const lastB = t.events.lastIndexOf(b);
    if (firstB >= 0) {
      bTraces += 1;
      if (firstA >= 0 && firstA < firstB) aPrecededB += 1;
    }
    if (firstA >= 0) {
      aTraces += 1;
      if (lastB > firstA) aFollowedByB += 1;
    }
  }
  if (bTraces >= 3 && aPrecededB === bTraces) rules.push({ kind: "always-precedes", first: a, second: b, support: bTraces });
  if (aTraces >= 3 && aFollowedByB === aTraces) rules.push({ kind: "always-pairs", first: a, second: b, support: aTraces });
}

export function mineTemporalProtocols(traces: readonly TemporalTraceSequence[]): TemporalProtocolSnapshot {
  if (!Array.isArray(traces)) throw new Error("traces must be an array.");
  const clean = traces.filter((t) => Array.isArray(t.events) && t.events.length >= 2);
  if (clean.length < 3) return { schemaVersion: 1, traceCount: clean.length, rules: [] };
  const alphabet = new Set<string>();
  for (const t of clean) for (const ev of t.events) if (typeof ev === "string" && ev.trim()) alphabet.add(ev.trim());
  const sorted = [...alphabet].sort();
  const rules: TemporalProtocolRule[] = [];
  for (const a of sorted) {
    for (const b of sorted) if (a !== b) evaluateTemporalPair(clean, a, b, rules);
  }
  return { schemaVersion: 1, traceCount: clean.length, rules };
}

export function compareTemporalProtocols(
  baseline: TemporalProtocolSnapshot,
  traces: readonly TemporalTraceSequence[],
  baselineFile = ".verification/protocols.json",
): TemporalProtocolDiff {
  if (!baseline) throw new Error("baseline is required.");
  const current = mineTemporalProtocols(traces);
  const violations: Finding[] = [];
  for (const rule of baseline.rules) {
    const brokenTraces: string[] = [];
    for (const t of traces) {
      const firstA = t.events.indexOf(rule.first);
      const firstB = t.events.indexOf(rule.second);
      const lastB = t.events.lastIndexOf(rule.second);
      if (rule.kind === "always-precedes" && firstB >= 0 && (firstA < 0 || firstA >= firstB)) brokenTraces.push(t.traceId);
      if (rule.kind === "always-pairs" && firstA >= 0 && lastB <= firstA) brokenTraces.push(t.traceId);
    }
    if (brokenTraces.length > 0) {
      violations.push({
        id: `PROTO:${rule.kind}:${rule.first}:${rule.second}`, rule: "temporal-protocol-violated",
        category: "oracle-lock", rung: "R3", severity: "error", soundness: "incorrectness-witness",
        file: baselineFile, line: 1,
        message: `Locked temporal API protocol '${rule.first} ${rule.kind} ${rule.second}' violated in trace(s): ${brokenTraces.slice(0, 5).join(", ")}.`,
        fix: `Restore call ordering (${rule.first} -> ${rule.second}) or update ${baselineFile} with explicit review.`,
      });
    }
  }
  const baseKeys = new Set(baseline.rules.map((r) => `${r.kind}:${r.first}:${r.second}`));
  const newRules = current.rules.filter((r) => !baseKeys.has(`${r.kind}:${r.first}:${r.second}`));
  return { passed: violations.length === 0, violations, newRules };
}

export function writeTemporalProtocols(filePath: string, snapshot: TemporalProtocolSnapshot): void {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  let existing: Record<string, unknown> = { schemaVersion: 1 };
  if (fs.existsSync(resolved)) {
    try { existing = JSON.parse(fs.readFileSync(resolved, "utf8")) as Record<string, unknown>; } catch { existing = { schemaVersion: 1 }; }
  }
  fs.writeFileSync(resolved, `${JSON.stringify({ ...existing, temporalProtocols: snapshot }, null, 2)}\n`, "utf8");
}
