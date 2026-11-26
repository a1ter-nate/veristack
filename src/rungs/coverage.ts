import type { DiscoveredRepo } from "../discover.ts";
import type { RepoArchetype, RungCheck, RungCoverageGrade, RungId, RungStatus, TestFileRecord } from "../types.ts";

interface E2eCap {
  min: number;
  max: number;
  label: string;
}

const E2E_CAP_BY_ARCHETYPE: Record<RepoArchetype, E2eCap> = {
  library: { min: 0, max: 0, label: "0 (not applicable)" },
  service: { min: 1, max: 3, label: "1–3 cross-service tasks" },
  frontend: { min: 1, max: 10, label: "5–10 golden journeys" },
  fullstack: { min: 1, max: 15, label: "5–15 golden journeys" },
};

interface RungBuilderInput {
  rung: RungId;
  name: string;
  speedBudget: string;
  targetBudget: string;
  idealCoverage: string;
  observedCoverage: string;
  observedCount: number;
  evidence: string[];
  gaps: string[];
  checks: RungCheck[];
  executedInCi: boolean;
  notApplicable?: boolean;
  overBudget?: boolean;
  overBudgetPenaltyScore?: number;
}

function finalizeRung(input: RungBuilderInput): RungStatus {
  if (input.notApplicable) {
    return {
      rung: input.rung,
      name: input.name,
      speedBudget: input.speedBudget,
      targetBudget: input.targetBudget,
      status: "not-applicable",
      coverageGrade: "not-applicable",
      coverageScore: 100,
      executedInCi: false,
      idealCoverage: input.idealCoverage,
      observedCoverage: input.observedCoverage,
      checks: input.checks,
      observedCount: input.observedCount,
      evidence: input.evidence,
      gaps: [],
    };
  }

  const totalWeight = input.checks.reduce((sum, c) => sum + c.weight, 0);
  const earnedWeight = input.checks.reduce((sum, c) => sum + (c.passed ? c.weight : 0), 0);
  let score = input.evidence.length === 0 ? 0 : totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;

  const gaps = [...input.gaps];
  if (!input.executedInCi && input.evidence.length > 0) {
    gaps.push(`Rung ${input.rung} is NOT executed in CI workflows — wire it into .github/workflows/ so it runs on the system`);
    score = Math.min(score, 50);
  } else if (!input.executedInCi && input.evidence.length === 0) {
    gaps.push(`Rung ${input.rung} is NOT executed in CI workflows`);
  }

  if (input.overBudget) {
    const penalty = input.overBudgetPenaltyScore ?? Math.min(score, 45);
    return {
      rung: input.rung,
      name: input.name,
      speedBudget: input.speedBudget,
      targetBudget: input.targetBudget,
      status: "over-budget",
      coverageGrade: "over-budget",
      coverageScore: Math.min(69, Math.max(0, penalty)),
      executedInCi: input.executedInCi,
      idealCoverage: input.idealCoverage,
      observedCoverage: input.observedCoverage,
      checks: input.checks,
      observedCount: input.observedCount,
      evidence: input.evidence,
      gaps,
    };
  }

  let coverageGrade: RungCoverageGrade;
  let status: RungStatus["status"];
  if (input.evidence.length === 0 || score < 25) {
    coverageGrade = "not-covered";
    status = "hole";
  } else if (!input.executedInCi || score < 80 || gaps.length > 0) {
    coverageGrade = "poorly-covered";
    status = "partial";
    if (score >= 80) score = 79;
  } else {
    coverageGrade = "well-covered";
    status = "covered";
  }

  return {
    rung: input.rung,
    name: input.name,
    speedBudget: input.speedBudget,
    targetBudget: input.targetBudget,
    status,
    coverageGrade,
    coverageScore: score,
    executedInCi: input.executedInCi,
    idealCoverage: input.idealCoverage,
    observedCoverage: input.observedCoverage,
    checks: input.checks,
    observedCount: input.observedCount,
    evidence: input.evidence,
    gaps,
  };
}

export function buildRungStatuses(repo: DiscoveredRepo, inventory: readonly TestFileRecord[]): RungStatus[] {
  const s = repo.signals;
  const ci = repo.ci;
  const isLib = repo.archetype === "library";
  const isFront = repo.archetype === "frontend";
  const isService = repo.archetype === "service" || repo.archetype === "fullstack";
  const isTs = repo.languages.includes("typescript") || repo.languages.includes("javascript");

  const prodFiles = repo.files.filter((f) => f.language && !f.isTest).length;
  const r2Files = inventory.filter((t) => t.rung === "R2");
  const r2Cases = r2Files.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0);
  const r3Files = inventory.filter((t) => t.rung === "R3");
  const r4Files = inventory.filter((t) => t.rung === "R4");
  const e2eFiles = inventory.filter((t) => t.rung === "R7");
  const e2eCases = e2eFiles.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0);
  const e2eCap = E2E_CAP_BY_ARCHETYPE[repo.archetype];

  const r0Evidence: string[] = [];
  const r0Gaps: string[] = [];
  const r0AntiSlopOk = !isTs || (s.hasAntiSlop && s.hasLandmines);
  if (s.hasFormatter) r0Evidence.push("formatter");
  else r0Gaps.push("Add deterministic formatter (.editorconfig / prettier / oxfmt / ruff / rustfmt)");
  if (s.hasLinter) r0Evidence.push(s.hasOxlint ? "oxlint" : "linter");
  else r0Gaps.push("Add fast linter (Oxlint / Roslyn / Ruff / Clippy / golangci-lint)");
  if (isTs && !s.hasAntiSlop) r0Gaps.push("Add anti-slop linter (veristack/lint or dmmulroy/anti-slop)");
  if (isTs && !s.hasLandmines) r0Gaps.push("Add test-integrity linter (veristack/lint or @interfere/landmines)");
  if (s.hasPreCommitHook) r0Evidence.push("pre-commit hook");
  else r0Gaps.push("Wire pre-commit hook (Lefthook) < 2s");
  if (s.hasCodeowners) r0Evidence.push("CODEOWNERS");
  else r0Gaps.push("Add CODEOWNERS locking acceptance specs & CI workflows");

  const r0 = finalizeRung({
    rung: "R0",
    name: "Instant Static, Anti-Slop & Locks",
    speedBudget: "< 2 s",
    targetBudget: "100% files",
    idealCoverage: "Formatter + fast linter/anti-slop + pre-commit hook + CODEOWNERS, running in CI",
    observedCoverage: `${r0Evidence.join(", ") || "none"} | CI: ${ci.runsFormatterOrLint ? "yes" : "no"}`,
    observedCount: r0Evidence.length,
    evidence: r0Evidence,
    gaps: r0Gaps,
    executedInCi: ci.runsFormatterOrLint,
    checks: [
      { id: "r0-formatter", label: "Formatter configured", weight: 20, passed: s.hasFormatter, executed: ci.runsFormatterOrLint, detail: s.hasFormatter ? "present" : "missing" },
      { id: "r0-linter", label: "Fast linter + anti-slop", weight: 25, passed: s.hasLinter && r0AntiSlopOk, executed: ci.runsFormatterOrLint, detail: s.hasLinter && r0AntiSlopOk ? "present" : "missing linter or anti-slop" },
      { id: "r0-precommit", label: "Pre-commit hook", weight: 15, passed: s.hasPreCommitHook, executed: s.hasPreCommitHook, detail: s.hasPreCommitHook ? "present" : "missing" },
      { id: "r0-codeowners", label: "CODEOWNERS lock", weight: 10, passed: s.hasCodeowners, executed: s.hasCodeowners, detail: s.hasCodeowners ? "present" : "missing" },
      { id: "r0-ci", label: "Executed in CI", weight: 30, passed: ci.runsFormatterOrLint, executed: ci.runsFormatterOrLint, detail: ci.runsFormatterOrLint ? "running in CI" : "not invoked in CI" },
    ],
  });

  const r1Evidence: string[] = [];
  const r1Gaps: string[] = [];
  const r1ArchOk = s.hasArchFitness || s.hasGoInternal || s.hasDeslopPlease;
  if (s.hasStrictTypes) r1Evidence.push(s.hasTsgo ? "strict types + tsgo" : "strict types");
  else r1Gaps.push("Enable strict compiler mode (strict: true / Nullable enable / mypy)");
  if (s.hasKnipOrDeadCode) r1Evidence.push("dead-code check");
  else r1Gaps.push("Add dead-code check (knip / noUnusedLocals / Roslyn CS0162+ / clippy)");
  if (r1ArchOk) r1Evidence.push("structural/arch check");
  else r1Gaps.push("Add structural boundary gate (veristack, deslop-please, go-internal, or arch-fitness)");

  const r1 = finalizeRung({
    rung: "R1",
    name: "Types, Deep-Module Structure & Ratchets",
    speedBudget: "1–10 s",
    targetBudget: "100% files",
    idealCoverage: "Strict types + dead-code check + structural/arch gate, running in CI",
    observedCoverage: `${r1Evidence.join(", ") || "none"} | CI: ${ci.runsTypeOrStructureCheck ? "yes" : "no"}`,
    observedCount: r1Evidence.length,
    evidence: r1Evidence,
    gaps: r1Gaps,
    executedInCi: ci.runsTypeOrStructureCheck,
    checks: [
      { id: "r1-types", label: "Strict type checking", weight: 30, passed: s.hasStrictTypes, executed: ci.runsTypeOrStructureCheck, detail: s.hasStrictTypes ? "enabled" : "missing" },
      { id: "r1-deadcode", label: "Dead-code check", weight: 20, passed: s.hasKnipOrDeadCode, executed: ci.runsTypeOrStructureCheck, detail: s.hasKnipOrDeadCode ? "present" : "missing" },
      { id: "r1-arch", label: "Structural/arch gate", weight: 20, passed: r1ArchOk, executed: ci.runsTypeOrStructureCheck, detail: r1ArchOk ? "present" : "missing" },
      { id: "r1-ci", label: "Executed in CI", weight: 30, passed: ci.runsTypeOrStructureCheck, executed: ci.runsTypeOrStructureCheck, detail: ci.runsTypeOrStructureCheck ? "running in CI" : "not invoked in CI" },
    ],
  });

  const idealR2Files = Math.max(1, Math.min(15, Math.ceil(Math.max(1, prodFiles) * 0.25)));
  const r2ScaledOk = r2Files.length >= idealR2Files || r2Cases >= Math.max(10, idealR2Files * 2);
  const r2HasTables = r2Files.some((f) => f.hasTable);
  const r2HasPbt = s.hasPbt || r2Files.some((f) => f.hasPbt);
  const r2Evidence: string[] = [];
  const r2Gaps: string[] = [];
  if (r2Files.length > 0) r2Evidence.push(`${r2Files.length} pure/unit test file(s) (${r2Cases} cases)`);
  else r2Gaps.push(`Add pure unit tests (ideal >= ${idealR2Files} file(s) for ${prodFiles} prod files)`);
  if (r2Files.length > 0 && !r2ScaledOk) {
    r2Gaps.push(`Unit test depth is sparse (${r2Files.length} file(s), ${r2Cases} cases vs ideal >= ${idealR2Files} files for ${prodFiles} prod files)`);
  }
  if (r2HasTables) r2Evidence.push("Tests-as-Data tables");
  else if (r2Files.length >= 3 || prodFiles >= 10) r2Gaps.push("Express multi-case matrices as Tests-as-Data tables");
  if (r2HasPbt) r2Evidence.push("Property-Based Tests");
  else r2Gaps.push("Add Property-Based Testing (fast-check / Hypothesis / FsCheck / proptest) for core invariants");

  const r2 = finalizeRung({
    rung: "R2",
    name: "Pure Logic, Tables & Stateless Oracles",
    speedBudget: "10 ms–2 s",
    targetBudget: "15–40 specs",
    idealCoverage: `>= ${idealR2Files} unit file(s) + Tests-as-Data tables + Property-Based Testing, running in CI`,
    observedCoverage: `${r2Files.length} file(s) / ${r2Cases} cases, tables=${r2HasTables ? "yes" : "no"}, PBT=${r2HasPbt ? "yes" : "no"} | CI: ${ci.runsUnitTests ? "yes" : "no"}`,
    observedCount: r2Files.length,
    evidence: r2Evidence,
    gaps: r2Gaps,
    executedInCi: ci.runsUnitTests && r2Files.length > 0,
    checks: [
      { id: "r2-unit-presence", label: "Pure unit suite exists", weight: 15, passed: r2Files.length > 0, executed: ci.runsUnitTests, detail: `${r2Files.length} file(s)` },
      { id: "r2-unit-depth", label: "Scales with prod surface", weight: 15, passed: r2ScaledOk, executed: ci.runsUnitTests, detail: `${r2Files.length}/${idealR2Files} target files` },
      { id: "r2-tables", label: "Tests-as-Data tables", weight: 20, passed: r2Files.length > 0 && (r2HasTables || (r2Files.length < 3 && prodFiles < 10)), executed: ci.runsUnitTests, detail: r2HasTables ? "present" : "missing" },
      { id: "r2-pbt", label: "Property-Based Testing", weight: 20, passed: r2HasPbt, executed: ci.runsUnitTests, detail: r2HasPbt ? "present" : "missing" },
      { id: "r2-ci", label: "Executed in CI", weight: 30, passed: ci.runsUnitTests && r2Files.length > 0, executed: ci.runsUnitTests, detail: ci.runsUnitTests ? "running in CI" : "not invoked in CI" },
    ],
  });

  const r3HasMbt = s.hasMbt || r3Files.some((f) => f.hasMbt);
  const r3NeedUi = isFront || repo.archetype === "fullstack";
  const r3UiOk = !r3NeedUi || (s.hasComponentUiTool && (!s.hasMsw || s.hasMswStrict));
  const r3ContractOk = !isService || s.hasContractTool;
  const r3LibBoundaryOk = !isLib || r3Files.length >= (prodFiles > 15 ? 2 : 1);
  const r3Evidence: string[] = [];
  const r3Gaps: string[] = [];
  if (r3Files.length > 0) r3Evidence.push(`${r3Files.length} in-process boundary suite(s)`);
  else r3Gaps.push("Add in-process boundary / host integration-lite suite(s)");
  if (r3HasMbt) r3Evidence.push("Stateful MBT");
  else r3Gaps.push("Add Stateful Model-Based Test for complex state machines / workflows");
  if (r3NeedUi) {
    if (s.hasComponentUiTool) r3Evidence.push("Component UI");
    else r3Gaps.push("Add Component UI tests (Testing Library / Playwright CT + strict MSW)");
    if (s.hasMsw && !s.hasMswStrict) r3Gaps.push("Set MSW onUnhandledRequest: 'error' (strict-msw)");
  }
  if (isService) {
    if (s.hasContractTool) r3Evidence.push("Contract tests");
    else r3Gaps.push("Add Producer/Consumer Contract tests (Pact / OpenAPI / AsyncAPI)");
  }
  if (isLib && r3Files.length > 0 && !r3LibBoundaryOk) {
    r3Gaps.push(`Add >= 2 in-process boundary suites for library surface (${r3Files.length} observed)`);
  }
  const r3ArchSpecificOk = r3UiOk && r3ContractOk && r3LibBoundaryOk;
  const r3CiExec = ci.runsBoundaryOrMbtTests && (r3Files.length > 0 || r3HasMbt);

  const r3 = finalizeRung({
    rung: "R3",
    name: "MBT, Component UI, Host, Contracts & Twins",
    speedBudget: "0.2–5 s",
    targetBudget: "5–15 suites",
    idealCoverage: isLib
      ? "In-process boundary suites (>= 2) + Stateful MBT, running in CI"
      : `${r3NeedUi ? "Component UI (+ strict MSW) + " : ""}${isService ? "Contracts + " : ""}boundary suites + Stateful MBT, running in CI`,
    observedCoverage: `${r3Files.length} suite(s), MBT=${r3HasMbt ? "yes" : "no"} | CI: ${r3CiExec ? "yes" : "no"}`,
    observedCount: r3Files.length,
    evidence: r3Evidence,
    gaps: r3Gaps,
    executedInCi: r3CiExec,
    checks: [
      { id: "r3-suites", label: "In-process boundary suites", weight: 25, passed: r3Files.length > 0, executed: r3CiExec, detail: `${r3Files.length} suite(s)` },
      { id: "r3-mbt", label: "Stateful MBT", weight: 25, passed: r3HasMbt, executed: r3CiExec, detail: r3HasMbt ? "present" : "missing" },
      { id: "r3-archetype", label: "Archetype boundary/UI/contracts", weight: 20, passed: r3ArchSpecificOk, executed: r3CiExec, detail: r3ArchSpecificOk ? "covered" : "incomplete" },
      { id: "r3-ci", label: "Executed in CI", weight: 30, passed: r3CiExec, executed: r3CiExec, detail: r3CiExec ? "running in CI" : "not invoked in CI" },
    ],
  });

  const r4Na = isLib || isFront;
  const r4HasReal = r4Files.length > 0 || s.hasTestcontainersOrRealDb;
  const r4Evidence: string[] = [];
  const r4Gaps: string[] = [];
  if (r4Na) {
    r4Evidence.push(`Not required for ${repo.archetype}`);
  } else {
    if (r4HasReal) r4Evidence.push(`${r4Files.length} real-engine integration file(s)`);
    else r4Gaps.push("Add isolated real-DB integration slices (Testcontainers / pglite / emulator)");
    if (s.hasMigrationTest) r4Evidence.push("migration check");
    else r4Gaps.push("Verify DB migrations against seeded old-schema rows");
    if (s.hasDst) r4Evidence.push("DST");
    if (s.hasDryRun) r4Evidence.push("dry-run check");
  }
  const r4CiExec = !r4Na && ci.runsIntegrationOrDbTests && r4HasReal;

  const r4 = finalizeRung({
    rung: "R4",
    name: "Real Engines, Migrations, Dry-Run & DST",
    speedBudget: "2–30 s",
    targetBudget: r4Na ? "0" : "3–8 slices",
    idealCoverage: r4Na ? "Not applicable" : ">= 3 real-engine integration slices + migration verification, running in CI",
    observedCoverage: r4Na ? "not applicable" : `${r4Files.length} file(s), migrations=${s.hasMigrationTest ? "yes" : "no"} | CI: ${r4CiExec ? "yes" : "no"}`,
    observedCount: r4Files.length,
    evidence: r4Evidence,
    gaps: r4Gaps,
    executedInCi: r4CiExec,
    notApplicable: r4Na,
    checks: r4Na
      ? []
      : [
          { id: "r4-real-engine", label: "Real-engine integration slices", weight: 40, passed: r4HasReal, executed: r4CiExec, detail: `${r4Files.length} file(s)` },
          { id: "r4-migrations", label: "Migration verification", weight: 30, passed: s.hasMigrationTest, executed: r4CiExec, detail: s.hasMigrationTest ? "present" : "missing" },
          { id: "r4-ci", label: "Executed in CI", weight: 30, passed: r4CiExec, executed: r4CiExec, detail: r4CiExec ? "running in CI" : "not invoked in CI" },
        ],
  });

  const r5NeedVisual = isFront || repo.archetype === "fullstack";
  const r5Evidence: string[] = [];
  const r5Gaps: string[] = [];
  if (s.hasMutationTool) r5Evidence.push("mutation/precision bench");
  else r5Gaps.push("Add targeted mutation testing (Stryker / mutmut / cargo-mutants) or precision bench");
  if (s.hasFormalTool) r5Evidence.push("formal verification");
  else r5Gaps.push("Add R5 formal spec or model check (Bend 2 / Quint / TLA+ / Z3 / Stateright / Kani)");
  if (s.hasFuzzTool) r5Evidence.push("fuzzing");
  if (s.hasBombadil) r5Evidence.push("Bombadil UI/TUI fuzzer");
  if (s.hasVisualTool) r5Evidence.push("visual regression");
  else if (r5NeedVisual) r5Gaps.push("Add visual regression (/ui-diff, Chromatic, Percy, or Playwright screenshots)");
  const r5CiExec = ci.runsMutationOrFormal && (s.hasMutationTool || s.hasFormalTool || s.hasVisualTool);

  const r5Checks: RungCheck[] = [
    { id: "r5-mutation", label: "Mutation or precision bench", weight: 35, passed: s.hasMutationTool, executed: r5CiExec, detail: s.hasMutationTool ? "present" : "missing" },
    { id: "r5-formal", label: "Formal spec / model check", weight: r5NeedVisual ? 20 : 35, passed: s.hasFormalTool, executed: r5CiExec, detail: s.hasFormalTool ? "present" : "missing" },
    ...(r5NeedVisual
      ? [{ id: "r5-visual", label: "Visual regression", weight: 15, passed: s.hasVisualTool, executed: r5CiExec, detail: s.hasVisualTool ? "present" : "missing" }]
      : []),
    { id: "r5-ci", label: "Executed in CI", weight: 30, passed: r5CiExec, executed: r5CiExec, detail: r5CiExec ? "running in CI" : "not invoked in CI" },
  ];

  const r5 = finalizeRung({
    rung: "R5",
    name: "Deep Exploration, Formal & Meta-Testing",
    speedBudget: "30 s–15 m",
    targetBudget: "Diff / Nightly",
    idealCoverage: r5NeedVisual
      ? "Mutation/precision bench + formal spec/model check + visual regression, running in CI"
      : "Mutation/precision bench + formal spec/model check, running in CI",
    observedCoverage: `${r5Evidence.join(", ") || "none"} | CI: ${r5CiExec ? "yes" : "no"}`,
    observedCount: r5Evidence.length,
    evidence: r5Evidence,
    gaps: r5Gaps,
    executedInCi: r5CiExec,
    checks: r5Checks,
  });

  const r6Evidence: string[] = [];
  const r6Gaps: string[] = [];
  if (s.hasPerfOrLoadTool) r6Evidence.push("perf/Big-O/load benchmark");
  else {
    r6Gaps.push(
      isFront
        ? "Add frontend perf budget (Lighthouse / web-vitals) in CI"
        : "Add comparable perf/Big-O/load benchmark (k6 / BenchmarkDotNet / criterion / vstack big-o)",
    );
  }
  if (s.hasDiffSelection) r6Evidence.push("diff-reachable PR test selection");
  const r6CiExec = ci.runsPerfOrBench && s.hasPerfOrLoadTool;

  const r6 = finalizeRung({
    rung: "R6",
    name: "Perf, Load Capacity & CI Telemetry",
    speedBudget: "2–30 m",
    targetBudget: isLib ? "1+ perf/Big-O gate" : "1–2 / svc",
    idealCoverage: isFront
      ? "Web-vitals / Lighthouse performance budget, running in CI"
      : "Comparable perf / Big-O / load benchmark with explicit budget, running in CI",
    observedCoverage: `${r6Evidence.join(", ") || "none"} | CI: ${r6CiExec ? "yes" : "no"}`,
    observedCount: r6Evidence.length,
    evidence: r6Evidence,
    gaps: r6Gaps,
    executedInCi: r6CiExec,
    checks: [
      { id: "r6-perf", label: "Perf / Big-O / load benchmark", weight: 70, passed: s.hasPerfOrLoadTool, executed: r6CiExec, detail: s.hasPerfOrLoadTool ? "present" : "missing" },
      { id: "r6-ci", label: "Executed in CI", weight: 30, passed: r6CiExec, executed: r6CiExec, detail: r6CiExec ? "running in CI" : "not invoked in CI" },
    ],
  });

  const r7Na = isLib && e2eCases === 0;
  const r7Over = e2eCases > e2eCap.max;
  const r7HasNetworkMock = e2eFiles.some((f) => f.hasNetworkMock);
  const r7Evidence: string[] = [];
  const r7Gaps: string[] = [];
  if (e2eFiles.length > 0) r7Evidence.push(`${e2eFiles.length} E2E file(s), ${e2eCases} case(s)`);
  if (r7Over) {
    r7Gaps.push(`E2E cases (${e2eCases}) exceed ${repo.archetype} cap (${e2eCap.label}); push matrices & stateful flows down to R2–R3`);
  } else if (!isLib && e2eFiles.length === 0) {
    r7Gaps.push(`Add ${e2eCap.label} covering real wiring + fresh-read persistence`);
  }
  if (!r7Na && r7HasNetworkMock) {
    r7Gaps.push("Remove mocked network routes from E2E tests — E2E must prove real end-to-end wiring");
  }
  const r7CiExec = !r7Na && ci.runsE2eTests && e2eFiles.length > 0;
  const r7WithinBudget = !r7Over && e2eCases >= e2eCap.min;

  const r7 = finalizeRung({
    rung: "R7",
    name: "Thin Golden-Path E2E & Hardware Proof",
    speedBudget: "2–15 m",
    targetBudget: e2eCap.label,
    idealCoverage: r7Na ? "Not applicable (0 E2E cap for library)" : `${e2eCap.label} with real wiring (no network mocks), running in CI`,
    observedCoverage: r7Na ? "not applicable" : `${e2eCases} case(s) across ${e2eFiles.length} file(s) (cap ${e2eCap.max}) | CI: ${r7CiExec ? "yes" : "no"}`,
    observedCount: e2eCases,
    evidence: r7Evidence,
    gaps: r7Gaps,
    executedInCi: r7CiExec,
    notApplicable: r7Na,
    overBudget: r7Over,
    overBudgetPenaltyScore: r7Over && e2eCases > 0 ? Math.round(((e2eCap.max > 0 ? e2eCap.max : 1) / e2eCases) * 100) : 0,
    checks: r7Na
      ? []
      : [
          { id: "r7-budget", label: "Golden-path E2E within cap", weight: 50, passed: r7WithinBudget, executed: r7CiExec, detail: `${e2eCases} case(s) vs cap ${e2eCap.max}` },
          { id: "r7-real-wiring", label: "Real wiring (no mocked network)", weight: 20, passed: e2eFiles.length > 0 && !r7HasNetworkMock, executed: r7CiExec, detail: r7HasNetworkMock ? "network mocked" : "real wiring" },
          { id: "r7-ci", label: "Executed in CI", weight: 30, passed: r7CiExec, executed: r7CiExec, detail: r7CiExec ? "running in CI" : "not invoked in CI" },
        ],
  });

  const r8Evidence: string[] = [];
  const r8Gaps: string[] = [];
  if (isLib) {
    r8Evidence.push("Not required for pure library");
  } else if (s.hasProdTelemetryOrCanary) {
    r8Evidence.push("prod telemetry / progressive delivery");
  } else {
    r8Gaps.push("Wire wide-event telemetry (OpenTelemetry), 3–10 synthetics, and canary/rollback rehearsal");
  }
  const r8CiExec = !isLib && ci.runsProdVerification && s.hasProdTelemetryOrCanary;

  const r8 = finalizeRung({
    rung: "R8",
    name: "Live Production Verification",
    speedBudget: "Continuous",
    targetBudget: isLib ? "0" : "3–10 probes",
    idealCoverage: isLib ? "Not applicable" : "OpenTelemetry/wide events + synthetics + canary/rollback workflow",
    observedCoverage: isLib ? "not applicable" : `${r8Evidence.join(", ") || "none"} | CI/workflow: ${r8CiExec ? "yes" : "no"}`,
    observedCount: r8Evidence.length,
    evidence: r8Evidence,
    gaps: r8Gaps,
    executedInCi: r8CiExec,
    notApplicable: isLib,
    checks: isLib
      ? []
      : [
          { id: "r8-telemetry", label: "Telemetry / canary instrumentation", weight: 70, passed: s.hasProdTelemetryOrCanary, executed: r8CiExec, detail: s.hasProdTelemetryOrCanary ? "present" : "missing" },
          { id: "r8-workflow", label: "Automated prod/canary check", weight: 30, passed: r8CiExec, executed: r8CiExec, detail: r8CiExec ? "wired in workflow" : "not wired in workflow" },
        ],
  });

  return [r0, r1, r2, r3, r4, r5, r6, r7, r8];
}
