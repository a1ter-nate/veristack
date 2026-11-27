import type { DiscoveredRepo } from "@veristack/plugin";
import type {
  RepoArchetype,
  RungCheck,
  RungId,
  RungReceipt,
  RungStatus,
  TestFileRecord,
} from "@veristack/plugin";
import { isHostRepoFile } from "@veristack/plugin";
import { buildWorkspaceLadders, finalizeRung } from "./workspaces.ts";

export { buildWorkspaceLadders };

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

export interface RungCoverageOptions {
  receipts?: Map<RungId, RungReceipt>;
  requireReceipts?: boolean;
}

interface RungBuildCtx {
  repo: DiscoveredRepo;
  isLib: boolean;
  isFront: boolean;
  isService: boolean;
  isTs: boolean;
  prodFiles: number;
  r2Files: readonly TestFileRecord[];
  r2Cases: number;
  r3Files: readonly TestFileRecord[];
  r4Files: readonly TestFileRecord[];
  e2eFiles: readonly TestFileRecord[];
  e2eCases: number;
  e2eCap: E2eCap;
  isExecuted: (rung: RungId, ciFlag: boolean) => { executed: boolean; receipt: RungReceipt | undefined };
}

function buildR0Status(ctx: RungBuildCtx): RungStatus {
  if (!ctx.repo) throw new Error("repo is required.");
  const { repo, isTs, isExecuted } = ctx;
  const s = repo.signals;
  const exec = isExecuted("R0", repo.ci.runsFormatterOrLint);
  const evidence: string[] = [];
  const gaps: string[] = [];
  const antiSlopOk = !isTs || (s.hasAntiSlop && s.hasLandmines);
  if (s.hasFormatter) evidence.push("formatter");
  else gaps.push("Add deterministic formatter (.editorconfig / prettier / oxfmt / ruff / rustfmt)");
  if (s.hasLinter) evidence.push(s.hasOxlint ? "oxlint" : "linter");
  else gaps.push("Add fast linter (Oxlint / Roslyn / Ruff / Clippy / golangci-lint)");
  if (isTs && !s.hasAntiSlop) gaps.push("Add anti-slop linter (veristack/lint or dmmulroy/anti-slop)");
  if (isTs && !s.hasLandmines) gaps.push("Add test-integrity linter (veristack/lint or @interfere/landmines)");
  if (s.hasPreCommitHook) evidence.push("pre-commit hook");
  else gaps.push("Wire non-empty pre-commit hook (Lefthook) < 2s");
  if (s.hasCodeowners) evidence.push("CODEOWNERS");
  else gaps.push("Lock .github/workflows/, .verification/, and CODEOWNERS in CODEOWNERS");
  return finalizeRung({
    rung: "R0", name: "Instant Static, Anti-Slop & Locks", speedBudget: "< 2 s", targetBudget: "100% files",
    idealCoverage: "Formatter + fast linter/anti-slop + pre-commit hook + CODEOWNERS, receipt-verified in CI",
    observedCoverage: `${evidence.join(", ") || "none"} | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: evidence.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt),
    checks: [
      { id: "r0-formatter", label: "Formatter configured", weight: 20, passed: s.hasFormatter, executed: exec.executed, detail: s.hasFormatter ? "present" : "missing" },
      { id: "r0-linter", label: "Fast linter + anti-slop", weight: 25, passed: s.hasLinter && antiSlopOk, executed: exec.executed, detail: s.hasLinter && antiSlopOk ? "present" : "missing" },
      { id: "r0-precommit", label: "Pre-commit hook", weight: 15, passed: s.hasPreCommitHook, executed: s.hasPreCommitHook, detail: s.hasPreCommitHook ? "present" : "missing" },
      { id: "r0-codeowners", label: "CODEOWNERS perimeter", weight: 10, passed: s.hasCodeowners, executed: s.hasCodeowners, detail: s.hasCodeowners ? "locked" : "incomplete/missing" },
      { id: "r0-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
    ],
  });
}

function buildR1Status(ctx: RungBuildCtx): RungStatus {
  const s = ctx.repo.signals;
  const exec = ctx.isExecuted("R1", ctx.repo.ci.runsTypeOrStructureCheck);
  const evidence: string[] = [];
  const gaps: string[] = [];
  const archOk = s.hasArchFitness || s.hasGoInternal || s.hasDeslopPlease;
  if (s.hasStrictTypes) evidence.push(s.hasTsgo ? "strict types + tsgo" : "strict types");
  else gaps.push("Enable strict compiler mode for every host language (strict: true / Nullable enable / mypy)");
  if (s.hasKnipOrDeadCode) evidence.push("dead-code check");
  else gaps.push("Add dead-code check (knip / noUnusedLocals / Roslyn CS0162+ / clippy)");
  if (archOk) evidence.push("structural/arch check");
  else gaps.push("Add structural boundary gate (check-max-lines, deslop-please, go-internal, or arch-fitness)");
  return finalizeRung({
    rung: "R1", name: "Types, Deep-Module Structure & Ratchets", speedBudget: "1–10 s", targetBudget: "100% files",
    idealCoverage: "Per-language strict types + dead-code + structural gate, receipt-verified in CI",
    observedCoverage: `${evidence.join(", ") || "none"} | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: evidence.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt),
    checks: [
      { id: "r1-types", label: "Strict type checking", weight: 30, passed: s.hasStrictTypes, executed: exec.executed, detail: s.hasStrictTypes ? "enabled" : "missing" },
      { id: "r1-deadcode", label: "Dead-code check", weight: 20, passed: s.hasKnipOrDeadCode, executed: exec.executed, detail: s.hasKnipOrDeadCode ? "present" : "missing" },
      { id: "r1-arch", label: "Structural/arch gate", weight: 20, passed: archOk, executed: exec.executed, detail: archOk ? "present" : "missing" },
      { id: "r1-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
    ],
  });
}

function buildR2Status(ctx: RungBuildCtx): { status: RungStatus; receipt: RungReceipt | undefined } {
  if (!ctx.repo) throw new Error("repo is required.");
  const { repo, prodFiles, r2Files, r2Cases, isExecuted } = ctx;
  const exec = isExecuted("R2", repo.ci.runsUnitTests && r2Files.length > 0);
  const idealR2Files = Math.max(1, Math.ceil(Math.max(1, prodFiles) * 0.2));
  const canaryReport = exec.receipt?.canary;
  const adequacyOk = r2Files.length >= idealR2Files && (!canaryReport || canaryReport.passed);
  const hasTables = r2Files.some((f) => f.hasTable);
  const hasPbt = repo.signals.hasPbt || r2Files.some((f) => f.hasPbt);
  const evidence: string[] = [];
  const gaps: string[] = [];
  if (r2Files.length > 0) evidence.push(`${r2Files.length} pure/unit test file(s) (${r2Cases} cases)`);
  else gaps.push(`Add pure unit tests (ideal >= ${idealR2Files} file(s) for ${prodFiles} host prod files)`);
  if (r2Files.length > 0 && !adequacyOk) {
    gaps.push(
      canaryReport
        ? `Planted-fault canary kill rate ${(canaryReport.killRate * 100).toFixed(0)}% < ${(canaryReport.minKillRate * 100).toFixed(0)}% (${canaryReport.survivedMutants} survivor(s))`
        : `Unit test depth is sparse (${r2Files.length} file(s) vs ideal >= ${idealR2Files} for ${prodFiles} prod files; or prove >=80% kill rate via canary receipt)`,
    );
  }
  if (hasTables) evidence.push("Tests-as-Data tables");
  else if (r2Files.length >= 3 || prodFiles >= 10) gaps.push("Express multi-case matrices as Tests-as-Data tables");
  if (hasPbt) evidence.push("Property-Based Tests");
  else gaps.push("Add real Property-Based Testing in host tests (fast-check / Hypothesis / FsCheck / proptest)");
  if (canaryReport?.passed) evidence.push(`canary kill ${(canaryReport.killRate * 100).toFixed(0)}%`);
  const status = finalizeRung({
    rung: "R2", name: "Pure Logic, Tables & Stateless Oracles", speedBudget: "10 ms–2 s", targetBudget: `>= ${idealR2Files} specs + canary`,
    idealCoverage: `>= ${idealR2Files} unit file(s) + >=75% planted-fault kill rate + Tables + PBT, receipt-verified`,
    observedCoverage: `${r2Files.length} file(s) / ${r2Cases} cases, tables=${hasTables ? "yes" : "no"}, PBT=${hasPbt ? "yes" : "no"}${canaryReport ? `, canary=${(canaryReport.killRate * 100).toFixed(0)}%` : ""} | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r2Files.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt), adequacyKillRate: canaryReport?.killRate,
    checks: [
      { id: "r2-unit-presence", label: "Pure unit suite exists", weight: 15, passed: r2Files.length > 0, executed: exec.executed, detail: `${r2Files.length} file(s)` },
      { id: "r2-adequacy", label: "Proportional depth / planted-fault adequacy", weight: 20, passed: r2Files.length > 0 && adequacyOk, executed: exec.executed, detail: canaryReport ? `${(canaryReport.killRate * 100).toFixed(0)}% killed` : `${r2Files.length}/${idealR2Files} files` },
      { id: "r2-tables", label: "Tests-as-Data tables", weight: 15, passed: r2Files.length > 0 && (hasTables || (r2Files.length < 3 && prodFiles < 10)), executed: exec.executed, detail: hasTables ? "present" : "missing" },
      { id: "r2-pbt", label: "Property-Based Testing", weight: 20, passed: hasPbt, executed: exec.executed, detail: hasPbt ? "present" : "missing" },
      { id: "r2-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
    ],
  });
  return { status, receipt: exec.receipt };
}

function buildR3Status(ctx: RungBuildCtx): RungStatus {
  if (!ctx.repo) throw new Error("repo is required.");
  const { repo, isLib, isFront, isService, prodFiles, r3Files, isExecuted } = ctx;
  const s = repo.signals;
  const hasMbt = s.hasMbt || r3Files.some((f) => f.hasMbt);
  const needUi = isFront || repo.archetype === "fullstack";
  const uiOk = !needUi || (s.hasComponentUiTool && (!s.hasMsw || s.hasMswStrict));
  const contractOk = !isService || s.hasContractTool;
  const libBoundaryOk = !isLib || r3Files.length >= (prodFiles > 15 ? 2 : 1);
  const exec = isExecuted("R3", repo.ci.runsBoundaryOrMbtTests && (r3Files.length > 0 || hasMbt));
  const evidence: string[] = [];
  const gaps: string[] = [];
  if (r3Files.length > 0) evidence.push(`${r3Files.length} in-process boundary suite(s)`);
  else gaps.push("Add in-process boundary / host integration-lite suite(s) in host tests");
  if (hasMbt) evidence.push("Stateful MBT");
  else gaps.push("Add real Stateful Model-Based Test in host tests (non-empty commands/state machine)");
  if (needUi) {
    if (s.hasComponentUiTool) evidence.push("Component UI");
    else gaps.push("Add Component UI tests (Testing Library / Playwright CT + strict MSW)");
    if (s.hasMsw && !s.hasMswStrict) gaps.push("Set MSW onUnhandledRequest: 'error' (strict-msw)");
  }
  if (isService) {
    if (s.hasContractTool) evidence.push("Contract tests");
    else gaps.push("Add Producer/Consumer Contract tests (Pact / OpenAPI / AsyncAPI)");
  }
  if (isLib && r3Files.length > 0 && !libBoundaryOk) gaps.push(`Add >= 2 in-process boundary suites for library surface (${r3Files.length} observed)`);
  const archOk = uiOk && contractOk && libBoundaryOk;
  return finalizeRung({
    rung: "R3", name: "MBT, Component UI, Host, Contracts & Twins", speedBudget: "0.2–5 s", targetBudget: "5–15 suites",
    idealCoverage: isLib ? "Host boundary suites (>= 2) + real Stateful MBT, receipt-verified in CI" : `${needUi ? "Component UI (+ strict MSW) + " : ""}${isService ? "Contracts + " : ""}boundary suites + Stateful MBT, receipt-verified`,
    observedCoverage: `${r3Files.length} suite(s), MBT=${hasMbt ? "yes" : "no"} | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r3Files.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt),
    checks: [
      { id: "r3-suites", label: "In-process boundary suites", weight: 25, passed: r3Files.length > 0, executed: exec.executed, detail: `${r3Files.length} suite(s)` },
      { id: "r3-mbt", label: "Stateful MBT", weight: 25, passed: hasMbt, executed: exec.executed, detail: hasMbt ? "present" : "missing" },
      { id: "r3-archetype", label: "Archetype boundary/UI/contracts", weight: 20, passed: archOk, executed: exec.executed, detail: archOk ? "covered" : "incomplete" },
      { id: "r3-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
    ],
  });
}

function buildR4Status(ctx: RungBuildCtx): RungStatus {
  const { repo, isLib, isFront, r4Files, isExecuted } = ctx;
  const s = repo.signals;
  const na = isLib || isFront;
  const hasReal = r4Files.length > 0 || s.hasTestcontainersOrRealDb;
  const exec = isExecuted("R4", !na && repo.ci.runsIntegrationOrDbTests && hasReal);
  const evidence: string[] = [];
  const gaps: string[] = [];
  if (na) evidence.push(`Not required for ${repo.archetype}`);
  else {
    if (hasReal) evidence.push(`${r4Files.length} real-engine integration file(s)`);
    else gaps.push("Add isolated real-DB integration slices (Testcontainers / pglite / emulator)");
    if (s.hasMigrationTest) evidence.push("migration check");
    else gaps.push("Verify DB migrations against seeded old-schema rows");
  }
  return finalizeRung({
    rung: "R4", name: "Real Engines, Migrations, Dry-Run & DST", speedBudget: "2–30 s", targetBudget: na ? "0" : "3–8 slices",
    idealCoverage: na ? "Not applicable" : ">= 3 real-engine integration slices + migration verification, receipt-verified",
    observedCoverage: na ? "not applicable" : `${r4Files.length} file(s), migrations=${s.hasMigrationTest ? "yes" : "no"} | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r4Files.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt), notApplicable: na,
    checks: na ? [] : [
      { id: "r4-real-engine", label: "Real-engine integration slices", weight: 40, passed: hasReal, executed: exec.executed, detail: `${r4Files.length} file(s)` },
      { id: "r4-migrations", label: "Migration verification", weight: 30, passed: s.hasMigrationTest, executed: exec.executed, detail: s.hasMigrationTest ? "present" : "missing" },
      { id: "r4-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
    ],
  });
}

function buildR5Status(ctx: RungBuildCtx, r2Receipt: RungReceipt | undefined): RungStatus {
  if (!ctx.repo) throw new Error("repo is required.");
  const { repo, isFront, isExecuted } = ctx;
  const s = repo.signals;
  const needVisual = isFront || repo.archetype === "fullstack";
  const hasFormalOrExplore = s.hasFormalTool || s.hasBombadil;
  const exec = isExecuted("R5", repo.ci.runsMutationOrFormal && (s.hasMutationTool || hasFormalOrExplore || s.hasVisualTool));
  const mutScore = exec.receipt?.metrics?.mutationScore;
  const receiptRanMutation = Boolean(exec.receipt) && /\b(?:canary|stryker|mutmut|cargo\s+mutants|gremlins|go-mutesting|pitest)\b/i.test(exec.receipt?.command ?? "");
  const hasMutation = (s.hasMutationTool || Boolean(exec.receipt?.canary?.passed) || receiptRanMutation) && (mutScore === undefined || mutScore >= 70);
  const evidence: string[] = [];
  const gaps: string[] = [];
  if (hasMutation) evidence.push(exec.receipt?.canary?.passed || r2Receipt?.canary?.passed ? "planted-fault mutation" : "mutation tool");
  else gaps.push("Add real mutation testing (Stryker / mutmut / cargo-mutants / vstack canary)");
  if (s.hasFormalTool) evidence.push("formal verification");
  else if (s.hasBombadil) evidence.push("autonomous property exploration (Bombadil)");
  else gaps.push("Add non-empty R5 formal spec/model check (Bend 2 / Quint / TLA+ / Z3 / Stateright / Kani)");
  if (s.hasVisualTool) evidence.push("visual regression");
  else if (needVisual) gaps.push("Add visual regression (/ui-diff, Chromatic, Percy, or Playwright screenshots)");
  const checks: RungCheck[] = [
    { id: "r5-mutation", label: "Real mutation / planted-fault proof", weight: 35, passed: hasMutation, executed: exec.executed, detail: hasMutation ? "present" : "missing" },
    { id: "r5-formal", label: "Formal spec / model check", weight: needVisual ? 20 : 35, passed: hasFormalOrExplore, executed: exec.executed, detail: hasFormalOrExplore ? "present" : "missing" },
    ...(needVisual ? [{ id: "r5-visual", label: "Visual regression", weight: 15, passed: s.hasVisualTool, executed: exec.executed, detail: s.hasVisualTool ? "present" : "missing" }] : []),
    { id: "r5-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
  ];
  return finalizeRung({
    rung: "R5", name: "Deep Exploration, Formal & Meta-Testing", speedBudget: "30 s–15 m", targetBudget: "Diff / Nightly",
    idealCoverage: needVisual ? "Real mutation testing + formal spec/model check + visual regression, receipt-verified" : "Real mutation testing + formal spec/model check, receipt-verified",
    observedCoverage: `${evidence.join(", ") || "none"} | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: evidence.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt), adequacyKillRate: exec.receipt?.canary?.killRate, checks,
  });
}

function buildR6Status(ctx: RungBuildCtx): RungStatus {
  const { repo, isLib, isFront, isExecuted } = ctx;
  const s = repo.signals;
  const exec = isExecuted("R6", repo.ci.runsPerfOrBench && s.hasPerfOrLoadTool);
  const evidence: string[] = [];
  const gaps: string[] = [];
  if (s.hasPerfOrLoadTool) evidence.push("perf/Big-O/load benchmark");
  else gaps.push(isFront ? "Add frontend perf budget (Lighthouse / web-vitals) in CI" : "Add comparable perf/Big-O/load benchmark (k6 / BenchmarkDotNet / criterion / vstack big-o)");
  if (s.hasDiffSelection) evidence.push("diff-reachable PR test selection");
  return finalizeRung({
    rung: "R6", name: "Perf, Load Capacity & CI Telemetry", speedBudget: "2–30 m", targetBudget: isLib ? "1+ perf/Big-O gate" : "1–2 / svc",
    idealCoverage: isFront ? "Web-vitals / Lighthouse performance budget, receipt-verified" : "Comparable perf / Big-O / load benchmark with explicit budget, receipt-verified",
    observedCoverage: `${evidence.join(", ") || "none"} | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: evidence.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt),
    checks: [
      { id: "r6-perf", label: "Perf / Big-O / load benchmark", weight: 70, passed: s.hasPerfOrLoadTool, executed: exec.executed, detail: s.hasPerfOrLoadTool ? "present" : "missing" },
      { id: "r6-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
    ],
  });
}

function buildR7Status(ctx: RungBuildCtx): RungStatus {
  const { repo, isLib, e2eFiles, e2eCases, e2eCap, isExecuted } = ctx;
  const na = isLib && e2eCases === 0;
  const over = e2eCases > e2eCap.max;
  const hasNetworkMock = e2eFiles.some((f) => f.hasNetworkMock);
  const exec = isExecuted("R7", !na && repo.ci.runsE2eTests && e2eFiles.length > 0);
  const evidence: string[] = e2eFiles.length > 0 ? [`${e2eFiles.length} E2E file(s), ${e2eCases} case(s)`] : [];
  const gaps: string[] = [];
  if (over) gaps.push(`E2E cases (${e2eCases}) exceed ${repo.archetype} cap (${e2eCap.label}); push matrices & stateful flows down to R2–R3`);
  else if (!isLib && e2eFiles.length === 0) gaps.push(`Add ${e2eCap.label} covering real wiring + fresh-read persistence`);
  if (!na && hasNetworkMock) gaps.push("Remove mocked network routes from E2E tests — E2E must prove real end-to-end wiring");
  return finalizeRung({
    rung: "R7", name: "Thin Golden-Path E2E & Hardware Proof", speedBudget: "2–15 m", targetBudget: e2eCap.label,
    idealCoverage: na ? "Not applicable (0 E2E cap for library)" : `${e2eCap.label} with real wiring (no network mocks), receipt-verified`,
    observedCoverage: na ? "not applicable" : `${e2eCases} case(s) across ${e2eFiles.length} file(s) (cap ${e2eCap.max}) | CI: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: e2eCases, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt),
    notApplicable: na, overBudget: over, overBudgetPenaltyScore: over && e2eCases > 0 ? Math.round(((e2eCap.max > 0 ? e2eCap.max : 1) / e2eCases) * 100) : 0,
    checks: na ? [] : [
      { id: "r7-budget", label: "Golden-path E2E within cap", weight: 50, passed: !over && e2eCases >= e2eCap.min, executed: exec.executed, detail: `${e2eCases} case(s) vs cap ${e2eCap.max}` },
      { id: "r7-real-wiring", label: "Real wiring (no mocked network)", weight: 20, passed: e2eFiles.length > 0 && !hasNetworkMock, executed: exec.executed, detail: hasNetworkMock ? "network mocked" : "real wiring" },
      { id: "r7-ci", label: "Executed in CI / receipt", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "active CI" : "not verified" },
    ],
  });
}

function buildR8Status(ctx: RungBuildCtx): RungStatus {
  const { repo, isLib, isExecuted } = ctx;
  const s = repo.signals;
  const exec = isExecuted("R8", !isLib && repo.ci.runsProdVerification && s.hasProdTelemetryOrCanary);
  const evidence: string[] = [];
  const gaps: string[] = [];
  if (isLib) evidence.push("Not required for pure library");
  else if (s.hasProdTelemetryOrCanary) evidence.push("prod telemetry / progressive delivery");
  else gaps.push("Wire wide-event telemetry (OpenTelemetry), 3–10 synthetics, and canary/rollback rehearsal");
  return finalizeRung({
    rung: "R8", name: "Live Production Verification", speedBudget: "Continuous", targetBudget: isLib ? "0" : "3–10 probes",
    idealCoverage: isLib ? "Not applicable" : "OpenTelemetry/wide events + synthetics + canary/rollback workflow",
    observedCoverage: isLib ? "not applicable" : `${evidence.join(", ") || "none"} | CI/workflow: ${exec.executed ? (exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: evidence.length, evidence, gaps, executedInCi: exec.executed, receiptVerified: Boolean(exec.receipt), notApplicable: isLib,
    checks: isLib ? [] : [
      { id: "r8-telemetry", label: "Telemetry / canary instrumentation", weight: 70, passed: s.hasProdTelemetryOrCanary, executed: exec.executed, detail: s.hasProdTelemetryOrCanary ? "present" : "missing" },
      { id: "r8-workflow", label: "Automated prod/canary check", weight: 30, passed: exec.executed, executed: exec.executed, detail: exec.receipt ? "receipt verified" : exec.executed ? "wired" : "not wired" },
    ],
  });
}

export function buildRungStatuses(
  repo: DiscoveredRepo,
  inventory: readonly TestFileRecord[],
  options: RungCoverageOptions = {},
): RungStatus[] {
  const receipts = options.receipts ?? new Map<RungId, RungReceipt>();
  const requireReceipts = Boolean(options.requireReceipts);
  const hostInventory = inventory.filter((t) => isHostRepoFile(t.file));
  const r2Files = hostInventory.filter((t) => t.rung === "R2");
  const e2eFiles = hostInventory.filter((t) => t.rung === "R7");
  const ctx: RungBuildCtx = {
    repo,
    isLib: repo.archetype === "library",
    isFront: repo.archetype === "frontend",
    isService: repo.archetype === "service" || repo.archetype === "fullstack",
    isTs: repo.languages.includes("typescript") || repo.languages.includes("javascript"),
    prodFiles: repo.files.filter((f) => f.language && !f.isTest && isHostRepoFile(f.rel)).length,
    r2Files,
    r2Cases: r2Files.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0),
    r3Files: hostInventory.filter((t) => t.rung === "R3"),
    r4Files: hostInventory.filter((t) => t.rung === "R4"),
    e2eFiles,
    e2eCases: e2eFiles.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0),
    e2eCap: E2E_CAP_BY_ARCHETYPE[repo.archetype],
    isExecuted: (rung, ciFlag) => {
      const rec = receipts.get(rung);
      if (requireReceipts) return { executed: Boolean(rec) && repo.ci.hasCiWorkflows && ciFlag, receipt: rec };
      if (rec) return { executed: repo.ci.hasCiWorkflows && ciFlag, receipt: rec };
      return { executed: ciFlag, receipt: undefined };
    },
  };
  const r2 = buildR2Status(ctx);
  return [
    buildR0Status(ctx), buildR1Status(ctx), r2.status, buildR3Status(ctx),
    buildR4Status(ctx), buildR5Status(ctx, r2.receipt), buildR6Status(ctx), buildR7Status(ctx), buildR8Status(ctx),
  ];
}
