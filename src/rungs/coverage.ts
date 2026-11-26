import type { DiscoveredRepo } from "../discover.ts";
import type {
  RepoArchetype,
  RungCheck,
  RungId,
  RungReceipt,
  RungStatus,
  TestFileRecord,
} from "../types.ts";
import { isHostRepoFile } from "./manifest.ts";
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

export function buildRungStatuses(
  repo: DiscoveredRepo,
  inventory: readonly TestFileRecord[],
  options: RungCoverageOptions = {},
): RungStatus[] {
  const s = repo.signals;
  const ci = repo.ci;
  const receipts = options.receipts ?? new Map<RungId, RungReceipt>();
  const requireReceipts = Boolean(options.requireReceipts);
  const isLib = repo.archetype === "library";
  const isFront = repo.archetype === "frontend";
  const isService = repo.archetype === "service" || repo.archetype === "fullstack";
  const isTs = repo.languages.includes("typescript") || repo.languages.includes("javascript");

  const hostInventory = inventory.filter((t) => isHostRepoFile(t.file));
  const prodFiles = repo.files.filter((f) => f.language && !f.isTest && isHostRepoFile(f.rel)).length;
  const r2Files = hostInventory.filter((t) => t.rung === "R2");
  const r2Cases = r2Files.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0);
  const r3Files = hostInventory.filter((t) => t.rung === "R3");
  const r4Files = hostInventory.filter((t) => t.rung === "R4");
  const e2eFiles = hostInventory.filter((t) => t.rung === "R7");
  const e2eCases = e2eFiles.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0);
  const e2eCap = E2E_CAP_BY_ARCHETYPE[repo.archetype];

  const isExecuted = (rung: RungId, ciFlag: boolean): { executed: boolean; receipt: RungReceipt | undefined } => {
    const rec = receipts.get(rung);
    if (requireReceipts) {
      return { executed: Boolean(rec) && ci.hasCiWorkflows && ciFlag, receipt: rec };
    }
    if (rec) return { executed: ci.hasCiWorkflows && ciFlag, receipt: rec };
    return { executed: ciFlag, receipt: undefined };
  };

  const r0Exec = isExecuted("R0", ci.runsFormatterOrLint);
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
  else r0Gaps.push("Wire non-empty pre-commit hook (Lefthook) < 2s");
  if (s.hasCodeowners) r0Evidence.push("CODEOWNERS");
  else r0Gaps.push("Lock .github/workflows/, .verification/, and CODEOWNERS in CODEOWNERS");

  const r0 = finalizeRung({
    rung: "R0",
    name: "Instant Static, Anti-Slop & Locks",
    speedBudget: "< 2 s",
    targetBudget: "100% files",
    idealCoverage: "Formatter + fast linter/anti-slop + pre-commit hook + CODEOWNERS, receipt-verified in CI",
    observedCoverage: `${r0Evidence.join(", ") || "none"} | CI: ${r0Exec.executed ? (r0Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r0Evidence.length,
    evidence: r0Evidence,
    gaps: r0Gaps,
    executedInCi: r0Exec.executed,
    receiptVerified: Boolean(r0Exec.receipt),
    checks: [
      { id: "r0-formatter", label: "Formatter configured", weight: 20, passed: s.hasFormatter, executed: r0Exec.executed, detail: s.hasFormatter ? "present" : "missing" },
      { id: "r0-linter", label: "Fast linter + anti-slop", weight: 25, passed: s.hasLinter && r0AntiSlopOk, executed: r0Exec.executed, detail: s.hasLinter && r0AntiSlopOk ? "present" : "missing" },
      { id: "r0-precommit", label: "Pre-commit hook", weight: 15, passed: s.hasPreCommitHook, executed: s.hasPreCommitHook, detail: s.hasPreCommitHook ? "present" : "missing" },
      { id: "r0-codeowners", label: "CODEOWNERS perimeter", weight: 10, passed: s.hasCodeowners, executed: s.hasCodeowners, detail: s.hasCodeowners ? "locked" : "incomplete/missing" },
      { id: "r0-ci", label: "Executed in CI / receipt", weight: 30, passed: r0Exec.executed, executed: r0Exec.executed, detail: r0Exec.receipt ? "receipt verified" : r0Exec.executed ? "active CI" : "not verified" },
    ],
  });

  const r1Exec = isExecuted("R1", ci.runsTypeOrStructureCheck);
  const r1Evidence: string[] = [];
  const r1Gaps: string[] = [];
  const r1ArchOk = s.hasArchFitness || s.hasGoInternal || s.hasDeslopPlease;
  if (s.hasStrictTypes) r1Evidence.push(s.hasTsgo ? "strict types + tsgo" : "strict types");
  else r1Gaps.push("Enable strict compiler mode for every host language (strict: true / Nullable enable / mypy)");
  if (s.hasKnipOrDeadCode) r1Evidence.push("dead-code check");
  else r1Gaps.push("Add dead-code check (knip / noUnusedLocals / Roslyn CS0162+ / clippy)");
  if (r1ArchOk) r1Evidence.push("structural/arch check");
  else r1Gaps.push("Add structural boundary gate (check-max-lines, deslop-please, go-internal, or arch-fitness)");

  const r1 = finalizeRung({
    rung: "R1",
    name: "Types, Deep-Module Structure & Ratchets",
    speedBudget: "1–10 s",
    targetBudget: "100% files",
    idealCoverage: "Per-language strict types + dead-code + structural gate, receipt-verified in CI",
    observedCoverage: `${r1Evidence.join(", ") || "none"} | CI: ${r1Exec.executed ? (r1Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r1Evidence.length,
    evidence: r1Evidence,
    gaps: r1Gaps,
    executedInCi: r1Exec.executed,
    receiptVerified: Boolean(r1Exec.receipt),
    checks: [
      { id: "r1-types", label: "Strict type checking", weight: 30, passed: s.hasStrictTypes, executed: r1Exec.executed, detail: s.hasStrictTypes ? "enabled" : "missing" },
      { id: "r1-deadcode", label: "Dead-code check", weight: 20, passed: s.hasKnipOrDeadCode, executed: r1Exec.executed, detail: s.hasKnipOrDeadCode ? "present" : "missing" },
      { id: "r1-arch", label: "Structural/arch gate", weight: 20, passed: r1ArchOk, executed: r1Exec.executed, detail: r1ArchOk ? "present" : "missing" },
      { id: "r1-ci", label: "Executed in CI / receipt", weight: 30, passed: r1Exec.executed, executed: r1Exec.executed, detail: r1Exec.receipt ? "receipt verified" : r1Exec.executed ? "active CI" : "not verified" },
    ],
  });

  const r2Exec = isExecuted("R2", ci.runsUnitTests && r2Files.length > 0);
  const idealR2Files = Math.max(1, Math.ceil(Math.max(1, prodFiles) * 0.2));
  const canaryReport = r2Exec.receipt?.canary;
  const r2AdequacyOk = r2Files.length >= idealR2Files && (!canaryReport || canaryReport.passed);
  const r2HasTables = r2Files.some((f) => f.hasTable);
  const r2HasPbt = s.hasPbt || r2Files.some((f) => f.hasPbt);
  const r2Evidence: string[] = [];
  const r2Gaps: string[] = [];
  if (r2Files.length > 0) r2Evidence.push(`${r2Files.length} pure/unit test file(s) (${r2Cases} cases)`);
  else r2Gaps.push(`Add pure unit tests (ideal >= ${idealR2Files} file(s) for ${prodFiles} host prod files)`);
  if (r2Files.length > 0 && !r2AdequacyOk) {
    r2Gaps.push(
      canaryReport
        ? `Planted-fault canary kill rate ${(canaryReport.killRate * 100).toFixed(0)}% < ${(canaryReport.minKillRate * 100).toFixed(0)}% (${canaryReport.survivedMutants} survivor(s))`
        : `Unit test depth is sparse (${r2Files.length} file(s) vs ideal >= ${idealR2Files} for ${prodFiles} prod files; or prove >=80% kill rate via canary receipt)`,
    );
  }
  if (r2HasTables) r2Evidence.push("Tests-as-Data tables");
  else if (r2Files.length >= 3 || prodFiles >= 10) r2Gaps.push("Express multi-case matrices as Tests-as-Data tables");
  if (r2HasPbt) r2Evidence.push("Property-Based Tests");
  else r2Gaps.push("Add real Property-Based Testing in host tests (fast-check / Hypothesis / FsCheck / proptest)");
  if (canaryReport?.passed) r2Evidence.push(`canary kill ${(canaryReport.killRate * 100).toFixed(0)}%`);

  const r2 = finalizeRung({
    rung: "R2",
    name: "Pure Logic, Tables & Stateless Oracles",
    speedBudget: "10 ms–2 s",
    targetBudget: `>= ${idealR2Files} specs + canary`,
    idealCoverage: `>= ${idealR2Files} unit file(s) + >=75% planted-fault kill rate + Tables + PBT, receipt-verified`,
    observedCoverage: `${r2Files.length} file(s) / ${r2Cases} cases, tables=${r2HasTables ? "yes" : "no"}, PBT=${r2HasPbt ? "yes" : "no"}${canaryReport ? `, canary=${(canaryReport.killRate * 100).toFixed(0)}%` : ""} | CI: ${r2Exec.executed ? (r2Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r2Files.length,
    evidence: r2Evidence,
    gaps: r2Gaps,
    executedInCi: r2Exec.executed,
    receiptVerified: Boolean(r2Exec.receipt),
    adequacyKillRate: canaryReport?.killRate,
    checks: [
      { id: "r2-unit-presence", label: "Pure unit suite exists", weight: 15, passed: r2Files.length > 0, executed: r2Exec.executed, detail: `${r2Files.length} file(s)` },
      { id: "r2-adequacy", label: "Proportional depth / planted-fault adequacy", weight: 20, passed: r2Files.length > 0 && r2AdequacyOk, executed: r2Exec.executed, detail: canaryReport ? `${(canaryReport.killRate * 100).toFixed(0)}% killed` : `${r2Files.length}/${idealR2Files} files` },
      { id: "r2-tables", label: "Tests-as-Data tables", weight: 15, passed: r2Files.length > 0 && (r2HasTables || (r2Files.length < 3 && prodFiles < 10)), executed: r2Exec.executed, detail: r2HasTables ? "present" : "missing" },
      { id: "r2-pbt", label: "Property-Based Testing", weight: 20, passed: r2HasPbt, executed: r2Exec.executed, detail: r2HasPbt ? "present" : "missing" },
      { id: "r2-ci", label: "Executed in CI / receipt", weight: 30, passed: r2Exec.executed, executed: r2Exec.executed, detail: r2Exec.receipt ? "receipt verified" : r2Exec.executed ? "active CI" : "not verified" },
    ],
  });

  const r3HasMbt = s.hasMbt || r3Files.some((f) => f.hasMbt);
  const r3NeedUi = isFront || repo.archetype === "fullstack";
  const r3UiOk = !r3NeedUi || (s.hasComponentUiTool && (!s.hasMsw || s.hasMswStrict));
  const r3ContractOk = !isService || s.hasContractTool;
  const r3LibBoundaryOk = !isLib || r3Files.length >= (prodFiles > 15 ? 2 : 1);
  const r3Exec = isExecuted("R3", ci.runsBoundaryOrMbtTests && (r3Files.length > 0 || r3HasMbt));
  const r3Evidence: string[] = [];
  const r3Gaps: string[] = [];
  if (r3Files.length > 0) r3Evidence.push(`${r3Files.length} in-process boundary suite(s)`);
  else r3Gaps.push("Add in-process boundary / host integration-lite suite(s) in host tests");
  if (r3HasMbt) r3Evidence.push("Stateful MBT");
  else r3Gaps.push("Add real Stateful Model-Based Test in host tests (non-empty commands/state machine)");
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

  const r3 = finalizeRung({
    rung: "R3",
    name: "MBT, Component UI, Host, Contracts & Twins",
    speedBudget: "0.2–5 s",
    targetBudget: "5–15 suites",
    idealCoverage: isLib
      ? "Host boundary suites (>= 2) + real Stateful MBT, receipt-verified in CI"
      : `${r3NeedUi ? "Component UI (+ strict MSW) + " : ""}${isService ? "Contracts + " : ""}boundary suites + Stateful MBT, receipt-verified`,
    observedCoverage: `${r3Files.length} suite(s), MBT=${r3HasMbt ? "yes" : "no"} | CI: ${r3Exec.executed ? (r3Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r3Files.length,
    evidence: r3Evidence,
    gaps: r3Gaps,
    executedInCi: r3Exec.executed,
    receiptVerified: Boolean(r3Exec.receipt),
    checks: [
      { id: "r3-suites", label: "In-process boundary suites", weight: 25, passed: r3Files.length > 0, executed: r3Exec.executed, detail: `${r3Files.length} suite(s)` },
      { id: "r3-mbt", label: "Stateful MBT", weight: 25, passed: r3HasMbt, executed: r3Exec.executed, detail: r3HasMbt ? "present" : "missing" },
      { id: "r3-archetype", label: "Archetype boundary/UI/contracts", weight: 20, passed: r3ArchSpecificOk, executed: r3Exec.executed, detail: r3ArchSpecificOk ? "covered" : "incomplete" },
      { id: "r3-ci", label: "Executed in CI / receipt", weight: 30, passed: r3Exec.executed, executed: r3Exec.executed, detail: r3Exec.receipt ? "receipt verified" : r3Exec.executed ? "active CI" : "not verified" },
    ],
  });

  const r4Na = isLib || isFront;
  const r4HasReal = r4Files.length > 0 || s.hasTestcontainersOrRealDb;
  const r4Exec = isExecuted("R4", !r4Na && ci.runsIntegrationOrDbTests && r4HasReal);
  const r4Evidence: string[] = [];
  const r4Gaps: string[] = [];
  if (r4Na) {
    r4Evidence.push(`Not required for ${repo.archetype}`);
  } else {
    if (r4HasReal) r4Evidence.push(`${r4Files.length} real-engine integration file(s)`);
    else r4Gaps.push("Add isolated real-DB integration slices (Testcontainers / pglite / emulator)");
    if (s.hasMigrationTest) r4Evidence.push("migration check");
    else r4Gaps.push("Verify DB migrations against seeded old-schema rows");
  }

  const r4 = finalizeRung({
    rung: "R4",
    name: "Real Engines, Migrations, Dry-Run & DST",
    speedBudget: "2–30 s",
    targetBudget: r4Na ? "0" : "3–8 slices",
    idealCoverage: r4Na ? "Not applicable" : ">= 3 real-engine integration slices + migration verification, receipt-verified",
    observedCoverage: r4Na ? "not applicable" : `${r4Files.length} file(s), migrations=${s.hasMigrationTest ? "yes" : "no"} | CI: ${r4Exec.executed ? (r4Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r4Files.length,
    evidence: r4Evidence,
    gaps: r4Gaps,
    executedInCi: r4Exec.executed,
    receiptVerified: Boolean(r4Exec.receipt),
    notApplicable: r4Na,
    checks: r4Na
      ? []
      : [
          { id: "r4-real-engine", label: "Real-engine integration slices", weight: 40, passed: r4HasReal, executed: r4Exec.executed, detail: `${r4Files.length} file(s)` },
          { id: "r4-migrations", label: "Migration verification", weight: 30, passed: s.hasMigrationTest, executed: r4Exec.executed, detail: s.hasMigrationTest ? "present" : "missing" },
          { id: "r4-ci", label: "Executed in CI / receipt", weight: 30, passed: r4Exec.executed, executed: r4Exec.executed, detail: r4Exec.receipt ? "receipt verified" : r4Exec.executed ? "active CI" : "not verified" },
        ],
  });

  const r5NeedVisual = isFront || repo.archetype === "fullstack";
  const r5Exec = isExecuted("R5", ci.runsMutationOrFormal && (s.hasMutationTool || s.hasFormalTool || s.hasVisualTool));
  const r5MutationScore = r5Exec.receipt?.metrics?.mutationScore;
  const r5MutationScoreOk = r5MutationScore === undefined || r5MutationScore >= 70;
  const r5ReceiptRanMutation =
    Boolean(r5Exec.receipt) &&
    /\b(?:canary|stryker|mutmut|cargo\s+mutants|gremlins|go-mutesting|pitest)\b/i.test(r5Exec.receipt?.command ?? "");
  const r5HasMutation =
    (s.hasMutationTool || Boolean(r5Exec.receipt?.canary?.passed) || r5ReceiptRanMutation) && r5MutationScoreOk;
  const r5Evidence: string[] = [];
  const r5Gaps: string[] = [];
  if (r5HasMutation) r5Evidence.push(r5Exec.receipt?.canary?.passed || r2Exec.receipt?.canary?.passed ? "planted-fault mutation" : "mutation tool");
  else r5Gaps.push("Add real mutation testing (Stryker / mutmut / cargo-mutants / vstack canary)");
  if (s.hasFormalTool) r5Evidence.push("formal verification");
  else r5Gaps.push("Add non-empty R5 formal spec/model check (Bend 2 / Quint / TLA+ / Z3 / Stateright / Kani)");
  if (s.hasVisualTool) r5Evidence.push("visual regression");
  else if (r5NeedVisual) r5Gaps.push("Add visual regression (/ui-diff, Chromatic, Percy, or Playwright screenshots)");

  const r5Checks: RungCheck[] = [
    { id: "r5-mutation", label: "Real mutation / planted-fault proof", weight: 35, passed: r5HasMutation, executed: r5Exec.executed, detail: r5HasMutation ? "present" : "missing" },
    { id: "r5-formal", label: "Formal spec / model check", weight: r5NeedVisual ? 20 : 35, passed: s.hasFormalTool, executed: r5Exec.executed, detail: s.hasFormalTool ? "present" : "missing" },
    ...(r5NeedVisual
      ? [{ id: "r5-visual", label: "Visual regression", weight: 15, passed: s.hasVisualTool, executed: r5Exec.executed, detail: s.hasVisualTool ? "present" : "missing" }]
      : []),
    { id: "r5-ci", label: "Executed in CI / receipt", weight: 30, passed: r5Exec.executed, executed: r5Exec.executed, detail: r5Exec.receipt ? "receipt verified" : r5Exec.executed ? "active CI" : "not verified" },
  ];

  const r5 = finalizeRung({
    rung: "R5",
    name: "Deep Exploration, Formal & Meta-Testing",
    speedBudget: "30 s–15 m",
    targetBudget: "Diff / Nightly",
    idealCoverage: r5NeedVisual
      ? "Real mutation testing + formal spec/model check + visual regression, receipt-verified"
      : "Real mutation testing + formal spec/model check, receipt-verified",
    observedCoverage: `${r5Evidence.join(", ") || "none"} | CI: ${r5Exec.executed ? (r5Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r5Evidence.length,
    evidence: r5Evidence,
    gaps: r5Gaps,
    executedInCi: r5Exec.executed,
    receiptVerified: Boolean(r5Exec.receipt),
    adequacyKillRate: r5Exec.receipt?.canary?.killRate,
    checks: r5Checks,
  });

  const r6Exec = isExecuted("R6", ci.runsPerfOrBench && s.hasPerfOrLoadTool);
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

  const r6 = finalizeRung({
    rung: "R6",
    name: "Perf, Load Capacity & CI Telemetry",
    speedBudget: "2–30 m",
    targetBudget: isLib ? "1+ perf/Big-O gate" : "1–2 / svc",
    idealCoverage: isFront
      ? "Web-vitals / Lighthouse performance budget, receipt-verified"
      : "Comparable perf / Big-O / load benchmark with explicit budget, receipt-verified",
    observedCoverage: `${r6Evidence.join(", ") || "none"} | CI: ${r6Exec.executed ? (r6Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r6Evidence.length,
    evidence: r6Evidence,
    gaps: r6Gaps,
    executedInCi: r6Exec.executed,
    receiptVerified: Boolean(r6Exec.receipt),
    checks: [
      { id: "r6-perf", label: "Perf / Big-O / load benchmark", weight: 70, passed: s.hasPerfOrLoadTool, executed: r6Exec.executed, detail: s.hasPerfOrLoadTool ? "present" : "missing" },
      { id: "r6-ci", label: "Executed in CI / receipt", weight: 30, passed: r6Exec.executed, executed: r6Exec.executed, detail: r6Exec.receipt ? "receipt verified" : r6Exec.executed ? "active CI" : "not verified" },
    ],
  });

  const r7Na = isLib && e2eCases === 0;
  const r7Over = e2eCases > e2eCap.max;
  const r7HasNetworkMock = e2eFiles.some((f) => f.hasNetworkMock);
  const r7Exec = isExecuted("R7", !r7Na && ci.runsE2eTests && e2eFiles.length > 0);
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
  const r7WithinBudget = !r7Over && e2eCases >= e2eCap.min;

  const r7 = finalizeRung({
    rung: "R7",
    name: "Thin Golden-Path E2E & Hardware Proof",
    speedBudget: "2–15 m",
    targetBudget: e2eCap.label,
    idealCoverage: r7Na ? "Not applicable (0 E2E cap for library)" : `${e2eCap.label} with real wiring (no network mocks), receipt-verified`,
    observedCoverage: r7Na ? "not applicable" : `${e2eCases} case(s) across ${e2eFiles.length} file(s) (cap ${e2eCap.max}) | CI: ${r7Exec.executed ? (r7Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: e2eCases,
    evidence: r7Evidence,
    gaps: r7Gaps,
    executedInCi: r7Exec.executed,
    receiptVerified: Boolean(r7Exec.receipt),
    notApplicable: r7Na,
    overBudget: r7Over,
    overBudgetPenaltyScore: r7Over && e2eCases > 0 ? Math.round(((e2eCap.max > 0 ? e2eCap.max : 1) / e2eCases) * 100) : 0,
    checks: r7Na
      ? []
      : [
          { id: "r7-budget", label: "Golden-path E2E within cap", weight: 50, passed: r7WithinBudget, executed: r7Exec.executed, detail: `${e2eCases} case(s) vs cap ${e2eCap.max}` },
          { id: "r7-real-wiring", label: "Real wiring (no mocked network)", weight: 20, passed: e2eFiles.length > 0 && !r7HasNetworkMock, executed: r7Exec.executed, detail: r7HasNetworkMock ? "network mocked" : "real wiring" },
          { id: "r7-ci", label: "Executed in CI / receipt", weight: 30, passed: r7Exec.executed, executed: r7Exec.executed, detail: r7Exec.receipt ? "receipt verified" : r7Exec.executed ? "active CI" : "not verified" },
        ],
  });

  const r8Exec = isExecuted("R8", !isLib && ci.runsProdVerification && s.hasProdTelemetryOrCanary);
  const r8Evidence: string[] = [];
  const r8Gaps: string[] = [];
  if (isLib) {
    r8Evidence.push("Not required for pure library");
  } else if (s.hasProdTelemetryOrCanary) {
    r8Evidence.push("prod telemetry / progressive delivery");
  } else {
    r8Gaps.push("Wire wide-event telemetry (OpenTelemetry), 3–10 synthetics, and canary/rollback rehearsal");
  }

  const r8 = finalizeRung({
    rung: "R8",
    name: "Live Production Verification",
    speedBudget: "Continuous",
    targetBudget: isLib ? "0" : "3–10 probes",
    idealCoverage: isLib ? "Not applicable" : "OpenTelemetry/wide events + synthetics + canary/rollback workflow",
    observedCoverage: isLib ? "not applicable" : `${r8Evidence.join(", ") || "none"} | CI/workflow: ${r8Exec.executed ? (r8Exec.receipt ? "receipt" : "yes") : "no"}`,
    observedCount: r8Evidence.length,
    evidence: r8Evidence,
    gaps: r8Gaps,
    executedInCi: r8Exec.executed,
    receiptVerified: Boolean(r8Exec.receipt),
    notApplicable: isLib,
    checks: isLib
      ? []
      : [
          { id: "r8-telemetry", label: "Telemetry / canary instrumentation", weight: 70, passed: s.hasProdTelemetryOrCanary, executed: r8Exec.executed, detail: s.hasProdTelemetryOrCanary ? "present" : "missing" },
          { id: "r8-workflow", label: "Automated prod/canary check", weight: 30, passed: r8Exec.executed, executed: r8Exec.executed, detail: r8Exec.receipt ? "receipt verified" : r8Exec.executed ? "wired" : "not wired" },
        ],
  });

  return [r0, r1, r2, r3, r4, r5, r6, r7, r8];
}
