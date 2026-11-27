import { auditAgentDocs } from "./anti-slop/agent-docs.ts";
import { auditCiWorkflows } from "./ci-auditor.ts";
import { discoverRepo, type DiscoveredRepo } from "./discover.ts";
import { auditRungCoverageFindings } from "./hooks/rung-gate.ts";
import { lintNoComments } from "./no-comments.ts";
import { buildRungStatuses, buildWorkspaceLadders } from "./rungs/coverage.ts";
import { auditDeclaredArchetype } from "./rungs/manifest.ts";
import { loadValidReceipts } from "./rungs/receipts.ts";
import { analyzeStructure } from "./structure.ts";
import { analyzeTests } from "./test-analyzer.ts";
import { analyzeTigerStyle, buildTigerStyleReport } from "./tigerstyle/index.ts";
import type { Finding, ScanReport, ScopeExclusion } from "./types.ts";
import { applyRepoConfig, isRuleDisabled, loadRepoConfig } from "./zero-defect/repo-config.ts";

export interface ScanOptions {
  configPath?: string;
  disableRules?: readonly string[];
  strict?: boolean;
  receiptHmacKey?: string;
}

const SAFE_ALLOW_EXCLUDED_PREFIX = /^(?:examples|fixtures|testdata|__fixtures__|snapshots)\//i;

function matchAllowPattern(pattern: string, target: string): boolean {
  const normPat = pattern.trim().replace(/^\/+/, "");
  const normTarget = target.replace(/^\/+/, "");
  if (!normPat) return false;
  if (normPat === normTarget) return true;
  const isDir = normPat.endsWith("/");
  const body = isDir ? normPat.slice(0, -1) : normPat;
  const escaped = body
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__DBL__")
    .replace(/\*/g, "[^/]*")
    .replace(/__DBL__/g, ".*");
  return new RegExp(`^${escaped}${isDir ? "(?:/.*)?$" : "$"}`).test(normTarget);
}

function filterUnallowlistedExclusions(
  exclusions: readonly ScopeExclusion[],
  allowExcluded: readonly string[],
): ScopeExclusion[] {
  if (allowExcluded.length === 0) return [...exclusions];
  return exclusions.filter((ex) => {
    if (ex.reason === "truncated") return true;
    const norm = ex.path.replace(/\\/g, "/").replace(/^\/+/, "");
    if (!SAFE_ALLOW_EXCLUDED_PREFIX.test(norm)) return true;
    return !allowExcluded.some((pat) => matchAllowPattern(pat, norm));
  });
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

function collectRawRepoFindings(
  repo: DiscoveredRepo,
  config: ReturnType<typeof loadRepoConfig>,
  options: ScanOptions,
): { rawFindings: Finding[]; testResult: ReturnType<typeof analyzeTests>; receipts: ReturnType<typeof loadValidReceipts>["receipts"] } {
  if (!repo.root) throw new Error("Discovered repo root is required.");
  const rawFindings: Finding[] = [];
  if (repo.manifestError) {
    rawFindings.push({
      id: "RUNG:manifest-invalid:.verification/rungs.json",
      rule: "rung-manifest-invalid",
      category: "oracle-lock",
      rung: "R0",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: repo.manifestError,
      fix: "Fix .verification/rungs.json schema so declared archetype and rung commands are valid.",
    });
  }
  rawFindings.push(...auditDeclaredArchetype(repo.manifest, repo.observedArchetype, repo));
  if (!isRuleDisabled("no-comments", config, options.disableRules)) {
    for (const file of repo.files) {
      if (file.language && !file.isStub) rawFindings.push(...lintNoComments(file.rel, file.content, file.language));
    }
  }
  const hookCfgFile = repo.files.find((f) => f.rel === ".verification/hooks.json");
  if (hookCfgFile) {
    try {
      const parsedHook = JSON.parse(hookCfgFile.content) as Record<string, unknown>;
      if (parsedHook.enabled === false) {
        rawFindings.push({
          id: "HOOK:disabled:.verification/hooks.json",
          rule: "hooks-disabled-in-config",
          category: "cheat",
          rung: "R0",
          severity: "error",
          file: ".verification/hooks.json",
          line: 1,
          message: ".verification/hooks.json sets enabled: false, disabling Veristack agent hooks.",
          fix: "Set enabled: true or run 'vstack hooks on' so per-edit and stop hooks remain active.",
        });
      }
    } catch { void 0; }
  }
  rawFindings.push(...analyzeStructure(repo), ...analyzeTigerStyle(repo), ...auditAgentDocs(repo));
  const testResult = analyzeTests(repo);
  rawFindings.push(...testResult.findings, ...auditCiWorkflows(repo));
  const receiptBundle = loadValidReceipts(repo, repo.manifest, { strict: options.strict, hmacKeyOverride: options.receiptHmacKey });
  rawFindings.push(...receiptBundle.findings);
  if (options.strict && repo.manifest?.rungs.R2 && !repo.manifest.rungs.R2.canary?.enabled) {
    rawFindings.push({
      id: "RUNG:r2-canary-required:.verification/rungs.json",
      rule: "rung-canary-required",
      category: "oracle-lock",
      rung: "R2",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: "Strict scan requires planted-fault canary (canary.enabled: true) on R2 so tests prove real fault detection.",
      fix: "Enable rungs.R2.canary in .verification/rungs.json.",
    });
  }
  return { rawFindings, testResult, receipts: receiptBundle.receipts };
}

function computeScanSummary(input: {
  repo: DiscoveredRepo;
  findings: readonly Finding[];
  rungs: ScanReport["rungs"];
  workspaces: NonNullable<ScanReport["workspaces"]>;
  testResult: ReturnType<typeof analyzeTests>;
  scopeExclusions: readonly ScopeExclusion[];
}): ScanReport["summary"] {
  const { repo, findings, rungs, workspaces, testResult, scopeExclusions } = input;
  if (!repo.root) throw new Error("Discovered repo root is required.");
  const sourceFiles = repo.files.filter((f) => f.language && !f.isTest);
  const testFiles = repo.files.filter((f) => f.language && f.isTest);
  const prodLines = sourceFiles.reduce((sum, f) => sum + f.lines, 0);
  const testLines = testFiles.reduce((sum, f) => sum + f.lines, 0);
  const e2eFiles = testResult.inventory.filter((t) => t.rung === "R7");
  const e2eTestCases = e2eFiles.reduce((sum, t) => sum + Math.max(1, t.testCaseCount), 0);

  const applicableRungs = rungs.filter((r) => r.coverageGrade !== "not-applicable");
  const wellCoveredCount = applicableRungs.filter((r) => r.coverageGrade === "well-covered").length;
  const poorlyCoveredCount = applicableRungs.filter((r) => r.coverageGrade === "poorly-covered").length;
  const holeCount = applicableRungs.filter((r) => r.coverageGrade === "not-covered" || r.coverageGrade === "over-budget").length;
  let overallCoverageScore =
    applicableRungs.length > 0
      ? Math.round(applicableRungs.reduce((sum, r) => sum + r.coverageScore, 0) / applicableRungs.length)
      : 100;
  if (workspaces.length > 0) {
    const minWs = Math.min(...workspaces.map((w) => w.score));
    if (minWs === 0) overallCoverageScore = 0;
    else {
      const avgWs = Math.round(workspaces.reduce((sum, w) => sum + w.score, 0) / workspaces.length);
      overallCoverageScore = Math.min(overallCoverageScore, Math.round((overallCoverageScore + avgWs) / 2));
    }
  }
  return {
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
    holeCount,
    poorlyCoveredCount,
    wellCoveredCount,
    applicableRungCount: applicableRungs.length,
    unexecutedRungCount: applicableRungs.filter((r) => !r.executedInCi).length,
    receiptVerifiedCount: applicableRungs.filter((r) => r.receiptVerified).length,
    excludedCount: scopeExclusions.length,
    overallCoverageScore,
  };
}

export function scanRepo(repoPath: string, options: ScanOptions = {}): ScanReport {
  if (!repoPath) throw new Error("Repository path is required.");
  const repo = discoverRepo(repoPath);
  const config = loadRepoConfig(repo.root, options.configPath);
  const { rawFindings, testResult, receipts } = collectRawRepoFindings(repo, config, options);
  const applied = applyRepoConfig(rawFindings, config, options.disableRules);
  const findings = applied.findings;
  const requireReceipts = Boolean(options.strict) || Boolean(repo.manifest);
  const rungs = buildRungStatuses(repo, testResult.inventory, { receipts, requireReceipts });
  if (options.strict) {
    findings.push(...auditRungCoverageFindings(repo, rungs, { requireWellCovered: true, respectRatchet: false }));
  }
  const tigerStyle = buildTigerStyleReport(repo, findings, rungs);
  const workspaces = buildWorkspaceLadders(repo, testResult.inventory, findings);
  const missingLinters = recommendMissingLinters(repo);
  const scopeExclusions = filterUnallowlistedExclusions(repo.scopeExclusions, repo.manifest?.allowExcluded ?? []);
  const hasActiveConfig = Boolean(config.configPath) || applied.disabledRules.length > 0 || config.ignore.length > 0;
  const summary = computeScanSummary({ repo, findings, rungs, workspaces, testResult, scopeExclusions });

  return {
    schemaVersion: 1,
    repo: repo.root,
    archetype: repo.archetype,
    ...(repo.manifest ? { declaredArchetype: repo.manifest.archetype } : {}),
    languages: repo.languages,
    ...(hasActiveConfig
      ? { config: { path: config.configPath, disabledRules: applied.disabledRules, suppressedCount: applied.suppressedCount } }
      : {}),
    summary,
    rungs,
    tigerStyle,
    ...(workspaces.length > 0 ? { workspaces } : {}),
    scopeExclusions,
    pushDownOpportunities: testResult.pushDownOpportunities,
    findings,
    missingLinters,
    testInventory: testResult.inventory,
  };
}
