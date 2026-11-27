import type {
  DiscoveredRepo,
  Finding,
  RungId,
  RungStatus,
  TigerStylePillar,
  TigerStylePrincipleStatus,
  TigerStyleReport,
} from "@veristack/plugin";
import { analyzeTigerAssertions } from "./assertions.ts";
import { analyzeTigerControlFlow } from "./control-flow.ts";
import { resolveTigerLang } from "./helpers.ts";
import { analyzeTigerInterfacesAndDeps, countDirectRuntimeDependencies } from "./interfaces-and-deps.ts";
import { analyzeTigerNaming } from "./naming.ts";
import { analyzeTigerTypesAndAlloc } from "./types-and-alloc.ts";

export function analyzeTigerStyleCore(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  for (const file of repo.files) {
    findings.push(...analyzeTigerControlFlow(file));
    findings.push(...analyzeTigerAssertions(file));
    findings.push(...analyzeTigerTypesAndAlloc(file));
    findings.push(...analyzeTigerNaming(file));
  }
  findings.push(...analyzeTigerInterfacesAndDeps(repo));
  return findings;
}

interface PrincipleInput {
  id: string;
  pillar: TigerStylePillar;
  name: string;
  rung: RungId;
  violations: number;
  applicable: boolean;
  observed: string;
  gap?: string;
}

function scorePrinciple(input: PrincipleInput): TigerStylePrincipleStatus {
  if (!input.applicable) {
    return {
      id: input.id, pillar: input.pillar, name: input.name, rung: input.rung,
      grade: "not-applicable", score: 100, mode: "gate", observed: input.observed, violationsCount: 0, gaps: [],
    };
  }
  const score = input.violations === 0 ? 100 : Math.max(0, 100 - Math.min(100, input.violations * 20));
  const grade = input.violations === 0 ? "strong" : score >= 50 ? "partial" : "missing";
  return {
    id: input.id, pillar: input.pillar, name: input.name, rung: input.rung,
    grade, score, mode: "gate", observed: input.observed, violationsCount: input.violations,
    gaps: input.violations > 0 && input.gap ? [input.gap] : [],
  };
}

function countRules(findings: readonly Finding[], rules: readonly string[]): number {
  const set = new Set(rules);
  let total = 0;
  for (const f of findings) if (set.has(f.rule)) total += 1;
  return total;
}

function hasEffectV4(repo: DiscoveredRepo): boolean {
  return repo.files.some((f) => /\bfrom\s+["'](?:effect(?:\/[^"']*)?|@effect\/[^"']*)["']/.test(f.content));
}

function buildSafetyPrinciples(
  repo: DiscoveredRepo,
  findings: readonly Finding[],
  rungs: readonly RungStatus[],
): TigerStylePrincipleStatus[] {
  const hasSys =
    repo.languages.some((l) => l === "rust" || l === "go" || l === "csharp" || l === "python" || l === "typescript") ||
    repo.files.some((f) => resolveTigerLang(f) === "sql");
  const r4 = rungs.find((r) => r.rung === "R4");
  const dstApplicable = repo.archetype === "service" || repo.archetype === "fullstack";
  const hasEffectDst = repo.files.some((f) => f.isTest && /\bTestClock\b/.test(f.content) && /\bTestRandom\b/.test(f.content));
  const dstOk = repo.signals.hasDst || hasEffectDst || r4?.coverageGrade === "well-covered";
  const c1 = countRules(findings, ["tiger-non-halting-assert", "tiger-low-assertion-density", "tiger-paired-write-read-assert", "no-release-stripped-assert", "effect-assertion-as-typed-error"]);
  const c2 = countRules(findings, ["tiger-no-recursion"]);
  const c3 = countRules(findings, ["tiger-unbounded-loop", "tiger-unbounded-queue", "effect-unbounded-concurrency", "effect-uncapped-retry-schedule"]);
  const c5 = countRules(findings, ["tiger-fixed-width-types"]);
  const c15 = findings.filter((f) => f.category === "cheat" || f.category === "no-comments").length;
  return [
    scorePrinciple({ id: "TS-01", pillar: "safety", name: "Production Assertions & Halt", rung: "R0", violations: c1, applicable: true, observed: c1 === 0 ? "0 stripped/non-halting/missing-density/unpaired issues" : `${c1} assertion issue(s)`, gap: "Enforce halting production assertions, >= 1 guard in >= 30L functions, and paired write/read validation." }),
    scorePrinciple({ id: "TS-02", pillar: "safety", name: "No Unbounded Recursion", rung: "R0", violations: c2, applicable: true, observed: c2 === 0 ? "0 unguarded recursive cycles" : `${c2} recursive cycle(s)`, gap: "Replace recursion with bounded explicit stacks/loops." }),
    scorePrinciple({ id: "TS-03", pillar: "safety", name: "Explicit Upper Bounds", rung: "R0", violations: c3, applicable: true, observed: c3 === 0 ? `0 unbounded loops/queues/concurrency${hasEffectV4(repo) ? " (Effect v4 checked)" : ""}` : `${c3} unbounded construct(s)`, gap: "Bound all loops, queues, retries, and Effect concurrency explicitly." }),
    scorePrinciple({ id: "TS-05", pillar: "safety", name: "Fixed-Width & Overflow Safe", rung: "R0", violations: c5, applicable: hasSys, observed: c5 === 0 ? "0 fixed-width/overflow/float-money issues" : `${c5} numeric type issue(s)`, gap: "Use fixed-width wire integers and checked/Decimal arithmetic." }),
    scorePrinciple({ id: "TS-14", pillar: "safety", name: "DST & Fault Models", rung: "R4", violations: dstApplicable && !dstOk ? 1 : 0, applicable: dstApplicable, observed: !dstApplicable ? `N/A for ${repo.archetype}` : dstOk ? "DST / real-engine fault simulation active" : "missing DST / fault simulation", gap: "Add deterministic simulation tests (Turmoil / Antithesis / Effect TestClock+TestRandom) and fault injection." }),
    scorePrinciple({ id: "TS-15", pillar: "safety", name: "Zero Technical Debt", rung: "R0", violations: c15, applicable: true, observed: c15 === 0 ? "0 cheats, 0 suppressions, 0 prose comments" : `${c15} debt/cheat/comment issue(s)`, gap: "Eliminate all anti-cheat, suppression, and prose-comment violations." }),
  ];
}

function buildPerfAndDxPrinciples(
  repo: DiscoveredRepo,
  findings: readonly Finding[],
  rungs: readonly RungStatus[],
): TigerStylePrincipleStatus[] {
  if (!repo.root) throw new Error("DiscoveredRepo.root must be non-empty");
  const hasAllocLang = repo.languages.some((l) => l === "rust" || l === "go" || l === "csharp") || hasEffectV4(repo);
  const depInfo = countDirectRuntimeDependencies(repo);
  const r6 = rungs.find((r) => r.rung === "R6");
  const hasBudgetFile = repo.allRelPaths.some((p) => p === ".verification/control-plan.json" || p === ".verification/budgets.json");
  const c4 = countRules(findings, ["tiger-function-length"]);
  const c6 = countRules(findings, ["tiger-hot-path-allocation", "effect-runtime-alloc-in-handler", "perf-loop-compile-or-deepcopy"]);
  const c7 = countRules(findings, ["tiger-push-ifs-up-fors-down"]);
  const c8 = countRules(findings, ["tiger-declare-near-use"]);
  const c9 = countRules(findings, ["tiger-interface-surface", "max-exports-per-module", "effect-large-service-interface", "no-implicit-state-machine"]);
  const c10 = countRules(findings, ["tiger-explicit-over-implicit"]);
  const c11 = countRules(findings, ["tiger-big-endian-naming"]);
  const c12 = countRules(findings, ["tiger-minimal-dependencies"]);
  const c13 = r6 && r6.coverageGrade !== "not-applicable" && r6.coverageGrade !== "well-covered" ? 1 : 0;
  return [
    scorePrinciple({ id: "TS-06", pillar: "performance", name: "Startup Allocation & Hot Paths", rung: "R0", violations: c6, applicable: hasAllocLang, observed: !hasAllocLang ? "N/A for pure GC/scripting repo" : c6 === 0 ? "0 hot-loop / per-request runtime allocations" : `${c6} hot-path allocation(s)`, gap: "Hoist allocations and Effect Layers/Queues to startup." }),
    scorePrinciple({ id: "TS-12", pillar: "performance", name: "Minimal Dependencies", rung: "R0", violations: c12, applicable: Boolean(depInfo.manifestFile), observed: depInfo.manifestFile ? `${depInfo.count} direct runtime dep(s) in ${depInfo.manifestFile}` : "no manifest", gap: "Trim direct runtime dependencies within cap and ratchet growth." }),
    scorePrinciple({ id: "TS-13", pillar: "performance", name: "Design-Time Budgets & Big-O", rung: "R6", violations: c13, applicable: Boolean(r6 && r6.coverageGrade !== "not-applicable"), observed: `${hasBudgetFile ? "control-plan budgets + " : ""}R6=${r6?.coverageGrade ?? "n/a"}`, gap: "Declare latency/memory/Big-O budgets and verify empirically in R6." }),
    scorePrinciple({ id: "TS-04", pillar: "developer-experience", name: "Function Length (<= 70 L)", rung: "R0", violations: c4, applicable: true, observed: c4 === 0 ? "all functions <= 70 lines" : `${c4} function(s) > 70 lines`, gap: "Refactor functions exceeding 70 lines into focused helpers." }),
    scorePrinciple({ id: "TS-07", pillar: "developer-experience", name: "Push Ifs Up, Fors Down", rung: "R1", violations: c7, applicable: true, observed: c7 === 0 ? "0 deep-nesting / cursor hotspots" : `${c7} control-flow shape issue(s)`, gap: "Flatten nesting (<= 4) with early returns and set-based batching." }),
    scorePrinciple({ id: "TS-08", pillar: "developer-experience", name: "Declare Variables Near Use", rung: "R0", violations: c8, applicable: repo.languages.some((l) => l === "typescript" || l === "javascript"), observed: c8 === 0 ? "0 variable hoist violations" : `${c8} distant variable declaration(s)`, gap: "Declare variables adjacent to first use in minimal scope." }),
    scorePrinciple({ id: "TS-09", pillar: "developer-experience", name: "Small Interfaces & Impossible States", rung: "R1", violations: c9, applicable: true, observed: c9 === 0 ? "0 wide signatures/flag-soup/implicit state machines" : `${c9} interface surface issue(s)`, gap: "Cap params <= 4, eliminate boolean flag soup, and keep traits/exports small." }),
    scorePrinciple({ id: "TS-10", pillar: "developer-experience", name: "Explicit Over Implicit", rung: "R0", violations: c10, applicable: true, observed: c10 === 0 ? "0 implicit timeout/wildcard defaults" : `${c10} implicit default(s)`, gap: "Pass explicit timeouts, column lists, and bounds at call sites." }),
    scorePrinciple({ id: "TS-11", pillar: "developer-experience", name: "Idiomatic Big-Endian Naming", rung: "R0", violations: c11, applicable: true, observed: c11 === 0 ? "0 inverted units/abbreviations/asymmetric pairs" : `${c11} naming issue(s)`, gap: "Use big-endian naming (latencyMsMax / latency_ms_max), unit suffixes, and symmetric pairs." }),
  ];
}

export function buildTigerStyleReport(
  repo: DiscoveredRepo,
  findings: readonly Finding[],
  rungs: readonly RungStatus[],
): TigerStyleReport {
  const principles = [...buildSafetyPrinciples(repo, findings, rungs), ...buildPerfAndDxPrinciples(repo, findings, rungs)];
  const applicable = principles.filter((p) => p.grade !== "not-applicable");
  const strongCount = applicable.filter((p) => p.grade === "strong").length;
  const partialCount = applicable.filter((p) => p.grade === "partial").length;
  const missingCount = applicable.filter((p) => p.grade === "missing").length;
  const overallScore =
    applicable.length > 0
      ? Math.round(applicable.reduce((acc, p) => acc + p.score, 0) / applicable.length)
      : 100;
  return { overallScore, applicableCount: applicable.length, strongCount, partialCount, missingCount, principles };
}
