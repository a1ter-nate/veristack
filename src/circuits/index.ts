import path from "node:path";
import { scanGitDiffCheats } from "../ci-auditor.ts";
import { discoverRepo } from "../discover.ts";
import { runGitClean } from "../rungs/config-audit.ts";
import { buildSystem1Packet } from "../system1-classifier.ts";
import type { CircuitId, CircuitMeta, CircuitRunReport } from "../types.ts";
import { analyzePerfHygiene } from "../zero-defect/perf-lints.ts";
import {
  DEFAULT_CIRCUITS,
  instructionLintPromoterCircuit,
  perfArchitectureAdvisorCircuit,
  prRiskRouterCircuit,
  testTriageCircuit,
  type InstructionRuleInput,
  type PerfAdvisorInput,
  type PrRiskInput,
  type TestTriageInput,
} from "./catalog.ts";
import { createSystem1Engine, runCircuit, type System1DecisionEngine } from "./engine.ts";

const ALREADY_ENFORCED_CLAUSE =
  /\b(?:no-comments|prose comments|as\s+any|as\s+unknown\s+as|--no-verify|continue-on-error|\|\|\s*true|pipe tests into|500 lines|<= 6)\b/i;

export { createSystem1Engine, runCircuit };

export function listDefaultCircuits(): readonly CircuitMeta[] {
  return DEFAULT_CIRCUITS;
}

function collectPrRiskInputs(repoPath: string, baseRef: string): PrRiskInput[] {
  const cheats = scanGitDiffCheats(repoPath, baseRef);
  const cheatFiles = new Set(cheats.map((c) => c.file));
  const numstat = runGitClean(repoPath, ["diff", "--numstat", baseRef], { maxBuffer: 2 * 1024 * 1024 });
  if (numstat.status !== 0 || !numstat.stdout.trim()) return [];

  const inputs: PrRiskInput[] = [];
  for (const line of numstat.stdout.trim().split(/\r?\n/)) {
    const parts = line.split("\t");
    const file = parts[2];
    if (!file) continue;
    const addedLines = Number(parts[0]) || 0;
    const removedLines = Number(parts[1]) || 0;
    const patch = runGitClean(repoPath, ["diff", "--unified=1", baseRef, "--", file], { maxBuffer: 256 * 1024 });
    inputs.push({
      file,
      addedLines,
      removedLines,
      diffSnippet: (patch.stdout ?? "").slice(0, 1800),
      hasCheatHit: cheatFiles.has(file),
    });
  }
  return inputs;
}

function collectInstructionInputs(repoPath: string): InstructionRuleInput[] {
  const repo = discoverRepo(repoPath);
  const items: InstructionRuleInput[] = [];
  for (const file of repo.files) {
    const base = path.posix.basename(file.rel).toLowerCase();
    if (base !== "agents.md" && base !== "claude.md" && base !== "skill.md") continue;
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const clause = (lines[i] ?? "").trim();
      if (!/^(?:\d+\.|-|\*)\s+/.test(clause) || clause.length < 20) continue;
      items.push({
        file: file.rel,
        line: i + 1,
        clause,
        alreadyEnforced: ALREADY_ENFORCED_CLAUSE.test(clause),
        hasConflict: /\b(?:skip|delete|weaken)\s+tests?\s+to\s+pass\b/i.test(clause),
      });
    }
  }
  return items;
}

function collectPerfAdvisorInputs(targetPath: string, maxCandidates: number): PerfAdvisorInput[] {
  const repo = discoverRepo(targetPath);
  const perfFindings = analyzePerfHygiene(repo);
  const hitsByFile = new Map<string, string[]>();
  for (const f of perfFindings) {
    const list = hitsByFile.get(f.file) ?? [];
    list.push(f.rule);
    hitsByFile.set(f.file, list);
  }
  const generatedPath =
    /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
  const prodFiles = repo.files
    .filter((f) => Boolean(f.language) && !f.isTest && !generatedPath.test(f.rel))
    .sort((a, b) => (hitsByFile.get(b.rel)?.length ?? 0) - (hitsByFile.get(a.rel)?.length ?? 0) || b.lines - a.lines)
    .slice(0, maxCandidates);
  return prodFiles.map((f) => ({
    file: f.rel,
    lines: f.lines,
    snippet: f.content,
    staticPerfHits: hitsByFile.get(f.rel) ?? [],
  }));
}

export async function runRepoCircuit(
  circuitId: CircuitId,
  targetPath: string,
  engine: System1DecisionEngine,
  options: { baseRef?: string; maxCandidates?: number } = {},
): Promise<CircuitRunReport> {
  if (!targetPath) throw new Error("Target path is required.");
  if (!engine.name) throw new Error("Decision engine name is required.");

  if (circuitId === "test-triage") {
    const packet = buildSystem1Packet(targetPath, { maxCandidates: options.maxCandidates ?? 30 });
    const repo = discoverRepo(targetPath);
    const byFile = new Map(repo.files.map((f) => [f.rel, f.content]));
    const inputs: TestTriageInput[] = packet.candidates
      .filter((c) => c.kind === "test")
      .map((facts) => ({
        file: facts.file,
        snippet: (byFile.get(facts.file) ?? "").slice(0, 1800),
        facts,
      }));
    return runCircuit(testTriageCircuit, inputs, engine);
  }
  if (circuitId === "pr-risk-router") {
    return runCircuit(prRiskRouterCircuit, collectPrRiskInputs(targetPath, options.baseRef ?? "HEAD"), engine);
  }
  if (circuitId === "instruction-lint-promoter") {
    return runCircuit(instructionLintPromoterCircuit, collectInstructionInputs(targetPath), engine);
  }
  return runCircuit(perfArchitectureAdvisorCircuit, collectPerfAdvisorInputs(targetPath, options.maxCandidates ?? 25), engine);
}

export function formatCircuitReport(report: CircuitRunReport): string {
  const pct = (report.shortCircuitRate * 100).toFixed(1);
  const lines = [
    `Circuit: ${report.circuitId} v${report.circuitVersion} (${report.circuitHash}) | Provider: ${report.provider}`,
    `Inputs: ${report.totalInputs} | Deterministic short-circuit: ${report.shortCircuitedCount} (${pct}%) | System 1 calls: ${report.modelCalledCount}`,
    `Bands: short_circuit=${report.bandCounts.short_circuit} high=${report.bandCounts.high} uncertain=${report.bandCounts.uncertain} low=${report.bandCounts.low} abstained=${report.bandCounts.abstained} contradicted=${report.bandCounts.contradicted}`,
  ];
  for (const r of report.receipts.slice(0, 30)) {
    const tag = r.shortCircuited ? "DET" : `S1:${r.band}`;
    const human = r.requiresHuman ? " [HUMAN]" : "";
    lines.push(`  - [${tag}] ${r.action}${human} :: ${r.subject} — ${r.reason}`);
  }
  return lines.join("\n");
}
