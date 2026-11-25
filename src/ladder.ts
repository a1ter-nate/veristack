import { auditCiWorkflows } from "./ci-auditor.ts";
import { discoverRepo, type DiscoveredRepo } from "./discover.ts";
import { lintNoComments } from "./no-comments.ts";
import { analyzeStructure } from "./structure.ts";
import { analyzeTests } from "./test-analyzer.ts";
import type { Finding, RepoArchetype, RungStatus, ScanReport, TestFileRecord } from "./types.ts";
import { auditAgentDocs } from "./anti-slop/agent-docs.ts";
import { applyRepoConfig, isRuleDisabled, loadRepoConfig } from "./zero-defect/repo-config.ts";

export interface ScanOptions {
  configPath?: string;
  disableRules?: readonly string[];
}

interface E2eCap {
  max: number;
  label: string;
}

const E2E_CAP_BY_ARCHETYPE: Record<RepoArchetype, E2eCap> = {
  library: { max: 0, label: "0 (not applicable)" },
  service: { max: 3, label: "1–3 cross-service tasks" },
  frontend: { max: 10, label: "5–10 golden journeys" },
  fullstack: { max: 15, label: "5–15 golden journeys" },
};

function buildRungStatuses(repo: DiscoveredRepo, inventory: readonly TestFileRecord[]): RungStatus[] {
  const s = repo.signals;
  const isLib = repo.archetype === "library";
  const isFront = repo.archetype === "frontend";
  const isService = repo.archetype === "service" || repo.archetype === "fullstack";
  const isTs = repo.languages.includes("typescript") || repo.languages.includes("javascript");

  const r2Files = inventory.filter((t) => t.rung === "R2");
  const r3Files = inventory.filter((t) => t.rung === "R3");
  const r4Files = inventory.filter((t) => t.rung === "R4");
  const e2eFiles = inventory.filter((t) => t.rung === "R7");
  const e2eCases = e2eFiles.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0);
  const e2eCap = E2E_CAP_BY_ARCHETYPE[repo.archetype];

  const r0Evidence: string[] = [];
  const r0Gaps: string[] = [];
  if (s.hasFormatter) r0Evidence.push("formatter");
  else r0Gaps.push("Add deterministic formatter");
  if (s.hasLinter) r0Evidence.push(s.hasOxlint ? "oxlint" : "linter");
  else r0Gaps.push("Add fast linter (Oxlint / Roslyn / Ruff / Clippy)");
  if (isTs && !s.hasAntiSlop) r0Gaps.push("Add dmmulroy/anti-slop Oxlint rules");
  if (isTs && !s.hasLandmines) r0Gaps.push("Add @interfere/landmines test-integrity Oxlint plugin");
  if (s.hasPreCommitHook) r0Evidence.push("pre-commit hook");
  else r0Gaps.push("Wire pre-commit hook (Lefthook) < 2s");
  if (s.hasCodeowners) r0Evidence.push("CODEOWNERS");
  else r0Gaps.push("Add CODEOWNERS locking acceptance specs & CI workflows");

  const r1Evidence: string[] = [];
  const r1Gaps: string[] = [];
  if (s.hasStrictTypes) r1Evidence.push(s.hasTsgo ? "strict types + tsgo" : "strict types");
  else r1Gaps.push("Enable strict compiler mode (strict: true / Nullable enable)");
  if (s.hasKnipOrDeadCode) r1Evidence.push("dead-code check");
  else r1Gaps.push("Add dead-code check (knip / Roslyn CS0162+)");
  if (s.hasArchFitness || s.hasGoInternal || s.hasDeslopPlease) r1Evidence.push("structural/arch check");
  else r1Gaps.push("Add structural boundary gate (deslop-please, oxlint-plugin-go-internal, or arch-fitness)");

  const r2Evidence: string[] = [];
  const r2Gaps: string[] = [];
  if (r2Files.length > 0) r2Evidence.push(`${r2Files.length} pure/unit test file(s)`);
  if (r2Files.some((f) => f.hasTable)) r2Evidence.push("Tests-as-Data tables");
  else if (r2Files.length >= 3) r2Gaps.push("Express multi-case matrices as CSV/YAML Tests-as-Data tables");
  if (s.hasPbt || r2Files.some((f) => f.hasPbt)) r2Evidence.push("Property-Based Tests");
  else r2Gaps.push("Add Property-Based Testing (fast-check / Hypothesis / FsCheck / proptest) for core invariants");

  const r3Evidence: string[] = [];
  const r3Gaps: string[] = [];
  if (r3Files.length > 0) r3Evidence.push(`${r3Files.length} in-process boundary suite(s)`);
  if (s.hasMbt || r3Files.some((f) => f.hasMbt)) r3Evidence.push("Stateful MBT");
  else r3Gaps.push("Add Stateful Model-Based Test for complex state machines / workflows");
  if (isFront || repo.archetype === "fullstack") {
    if (s.hasComponentUiTool) r3Evidence.push("Component UI");
    else r3Gaps.push("Add Component UI tests (Testing Library / Playwright CT + strict MSW)");
    if (s.hasMsw && !s.hasMswStrict) r3Gaps.push("Set MSW onUnhandledRequest: 'error' (strict-msw)");
  }
  if (isService) {
    if (s.hasContractTool) r3Evidence.push("Contract tests");
    else r3Gaps.push("Add Producer/Consumer Contract tests (Pact / OpenAPI / AsyncAPI)");
  }

  const r4Evidence: string[] = [];
  const r4Gaps: string[] = [];
  if (isLib) {
    r4Evidence.push("Not required for pure library");
  } else {
    if (r4Files.length > 0 || s.hasTestcontainersOrRealDb) r4Evidence.push(`${r4Files.length} real-engine integration file(s)`);
    else if (isService) r4Gaps.push("Add isolated real-DB integration slice (Testcontainers + 1s schema snapshot)");
    if (s.hasMigrationTest) r4Evidence.push("migration check");
    else if (isService) r4Gaps.push("Verify DB migrations against seeded old-schema rows");
    if (s.hasDst) r4Evidence.push("DST");
    if (s.hasDryRun) r4Evidence.push("dry-run check");
  }

  const r5Evidence: string[] = [];
  const r5Gaps: string[] = [];
  if (s.hasMutationTool) r5Evidence.push("mutation testing");
  else r5Gaps.push("Add targeted mutation testing (Stryker / mutmut / cargo-mutants) on critical diffs");
  if (s.hasFormalTool) r5Evidence.push("formal verification");
  else if (isService || s.hasMbt) {
    r5Gaps.push("Add R5 formal spec or model check (Quint/TLA+, Z3 SMT, Stateright/Kani) for critical state machines/protocols");
  }
  if (s.hasFuzzTool) r5Evidence.push("fuzzing");
  if (s.hasBombadil) r5Evidence.push("Bombadil UI/TUI fuzzer");
  if (s.hasVisualTool) r5Evidence.push("visual regression");
  else if (isFront || repo.archetype === "fullstack") r5Gaps.push("Add visual regression (/ui-diff, /gridlines, or Playwright screenshots)");

  const r6Evidence: string[] = [];
  const r6Gaps: string[] = [];
  if (s.hasPerfOrLoadTool) r6Evidence.push("perf/load tooling");
  else if (isService) r6Gaps.push("Add comparable perf bounds & k6 stress/spike/soak profile");
  if (s.hasDiffSelection) r6Evidence.push("diff-reachable PR test selection");

  const r7Evidence: string[] = [];
  const r7Gaps: string[] = [];
  if (e2eFiles.length > 0) r7Evidence.push(`${e2eFiles.length} E2E file(s), ${e2eCases} case(s)`);
  if (e2eCases > e2eCap.max) {
    r7Gaps.push(`E2E cases (${e2eCases}) exceed ${repo.archetype} cap (${e2eCap.label}); push matrices & stateful flows down to R2–R3`);
  } else if (!isLib && e2eFiles.length === 0) {
    r7Gaps.push(`Add ${e2eCap.label} covering real wiring + fresh-read persistence`);
  }

  const r8Evidence: string[] = [];
  const r8Gaps: string[] = [];
  if (isLib) {
    r8Evidence.push("Not required for pure library");
  } else if (s.hasProdTelemetryOrCanary) {
    r8Evidence.push("prod telemetry / progressive delivery");
  } else {
    r8Gaps.push("Wire wide-event telemetry, 3–10 synthetics, and canary/rollback rehearsal");
  }

  const statusFor = (ev: string[], gaps: string[], na = false, over = false): RungStatus["status"] => {
    if (na) return "not-applicable";
    if (over) return "over-budget";
    if (ev.length === 0 && gaps.length > 0) return "hole";
    if (gaps.length > 0) return "partial";
    return "covered";
  };

  return [
    { rung: "R0", name: "Instant Static, Anti-Slop & Locks", speedBudget: "< 2 s", targetBudget: "100% files", status: statusFor(r0Evidence, r0Gaps), observedCount: r0Evidence.length, evidence: r0Evidence, gaps: r0Gaps },
    { rung: "R1", name: "Types, Deep-Module Structure & Ratchets", speedBudget: "1–10 s", targetBudget: "100% files", status: statusFor(r1Evidence, r1Gaps), observedCount: r1Evidence.length, evidence: r1Evidence, gaps: r1Gaps },
    { rung: "R2", name: "Pure Logic, Tables & Stateless Oracles", speedBudget: "10 ms–2 s", targetBudget: "15–40 specs", status: statusFor(r2Evidence, r2Gaps), observedCount: r2Files.length, evidence: r2Evidence, gaps: r2Gaps },
    { rung: "R3", name: "MBT, Component UI, Host, Contracts & Twins", speedBudget: "0.2–5 s", targetBudget: "5–15 suites", status: statusFor(r3Evidence, r3Gaps), observedCount: r3Files.length, evidence: r3Evidence, gaps: r3Gaps },
    { rung: "R4", name: "Real Engines, Migrations, Dry-Run & DST", speedBudget: "2–30 s", targetBudget: isLib ? "0" : "3–8 slices", status: statusFor(r4Evidence, r4Gaps, isLib), observedCount: r4Files.length, evidence: r4Evidence, gaps: r4Gaps },
    { rung: "R5", name: "Deep Exploration, Formal & Meta-Testing", speedBudget: "30 s–15 m", targetBudget: "Diff / Nightly", status: statusFor(r5Evidence, r5Gaps), observedCount: r5Evidence.length, evidence: r5Evidence, gaps: r5Gaps },
    { rung: "R6", name: "Perf, Load Capacity & CI Telemetry", speedBudget: "2–30 m", targetBudget: "1–2 / svc", status: statusFor(r6Evidence, r6Gaps, isLib && r6Evidence.length === 0), observedCount: r6Evidence.length, evidence: r6Evidence, gaps: r6Gaps },
    { rung: "R7", name: "Thin Golden-Path E2E & Hardware Proof", speedBudget: "2–15 m", targetBudget: e2eCap.label, status: statusFor(r7Evidence, r7Gaps, isLib && e2eCases === 0, e2eCases > e2eCap.max), observedCount: e2eCases, evidence: r7Evidence, gaps: r7Gaps },
    { rung: "R8", name: "Live Production Verification", speedBudget: "Continuous", targetBudget: isLib ? "0" : "3–10 probes", status: statusFor(r8Evidence, r8Gaps, isLib), observedCount: r8Evidence.length, evidence: r8Evidence, gaps: r8Gaps },
  ];
}

function recommendMissingLinters(repo: DiscoveredRepo): ScanReport["missingLinters"] {
  const s = repo.signals;
  const isTs = repo.languages.includes("typescript") || repo.languages.includes("javascript");
  const isCs = repo.languages.includes("csharp");
  const missing: ScanReport["missingLinters"] = [];

  if (isTs && !s.hasOxlint) missing.push({ tool: "oxlint", priority: "P1", why: "50–100x faster Rust linter for JS/TS with JS plugin support." });
  if (isTs && !s.hasAntiSlop) missing.push({ tool: "dmmulroy/anti-slop", priority: "P1", why: "Blocks 15 TS escape-hatch & untyped contract slop patterns." });
  if (isTs && !s.hasLandmines) missing.push({ tool: "@interfere/landmines", priority: "P1", why: "Blocks test doubles, sleeps, retries, conditional expects & parameter branches." });
  if (!s.hasDeslopPlease) missing.push({ tool: "deslop-please", priority: "P2", why: "SCIP-graph Ousterhout linter (field-leak, shallow-module, tangle, cycle) that cuts agent tokens/task." });
  if (isTs && !s.hasGoInternal) missing.push({ tool: "oxlint-plugin-go-internal", priority: "P2", why: "Enforces Go-style internal/ encapsulation across TS feature modules." });
  if (isTs && !s.hasKnipOrDeadCode) missing.push({ tool: "knip", priority: "P2", why: "Deletes dead files, unused exports/types & phantom dependencies agents copy." });
  if (isCs && !s.hasDesloppify) missing.push({ tool: "desloppify", priority: "P2", why: "Full C# + TS structural quality harness with CI scoring." });
  if (!s.hasPreCommitHook) missing.push({ tool: "lefthook", priority: "P3", why: "Runs formatter, no-comments, and fast lints in < 2s before push." });

  return missing;
}

export function scanRepo(repoPath: string, options: ScanOptions = {}): ScanReport {
  const repo = discoverRepo(repoPath);
  const config = loadRepoConfig(repo.root, options.configPath);
  const rawFindings: Finding[] = [];

  if (!isRuleDisabled("no-comments", config, options.disableRules)) {
    for (const file of repo.files) {
      if (file.language) {
        rawFindings.push(...lintNoComments(file.rel, file.content, file.language));
      }
    }
  }

  rawFindings.push(...analyzeStructure(repo));
  rawFindings.push(...auditAgentDocs(repo));
  const testResult = analyzeTests(repo);
  rawFindings.push(...testResult.findings);
  rawFindings.push(...auditCiWorkflows(repo));

  const applied = applyRepoConfig(rawFindings, config, options.disableRules);
  const findings = applied.findings;

  const rungs = buildRungStatuses(repo, testResult.inventory);
  const missingLinters = recommendMissingLinters(repo);

  const sourceFiles = repo.files.filter((f) => f.language && !f.isTest);
  const testFiles = repo.files.filter((f) => f.language && f.isTest);
  const prodLines = sourceFiles.reduce((sum, f) => sum + f.lines, 0);
  const testLines = testFiles.reduce((sum, f) => sum + f.lines, 0);
  const e2eFiles = testResult.inventory.filter((t) => t.rung === "R7");
  const e2eTestCases = e2eFiles.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0);
  const hasActiveConfig = Boolean(config.configPath) || applied.disabledRules.length > 0;

  return {
    schemaVersion: 1,
    repo: repo.root,
    archetype: repo.archetype,
    languages: repo.languages,
    ...(hasActiveConfig
      ? {
          config: {
            path: config.configPath,
            disabledRules: applied.disabledRules,
            suppressedCount: applied.suppressedCount,
          },
        }
      : {}),
    summary: {
      sourceFiles: sourceFiles.length,
      testFiles: testFiles.length,
      prodLines,
      testLines,
      testToProdRatio: prodLines > 0 ? Number((testLines / prodLines).toFixed(2)) : 0,
      e2eFiles: e2eFiles.length,
      e2eTestCases,
      totalFindings: findings.length,
      errorCount: findings.filter((f) => f.severity === "error").length,
      warnCount: findings.filter((f) => f.severity === "warn").length,
      cheatCount: findings.filter((f) => f.category === "cheat").length,
      noCommentCount: findings.filter((f) => f.category === "no-comments").length,
      pushDownCount: testResult.pushDownOpportunities.length,
      holeCount: rungs.filter((r) => r.status === "hole" || r.status === "over-budget").length,
    },
    rungs,
    pushDownOpportunities: testResult.pushDownOpportunities,
    findings,
    missingLinters,
    testInventory: testResult.inventory,
  };
}
