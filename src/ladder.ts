import { auditAgentDocs } from "./anti-slop/agent-docs.ts";
import { auditCiWorkflows } from "./ci-auditor.ts";
import { discoverRepo, type DiscoveredRepo } from "./discover.ts";
import { lintNoComments } from "./no-comments.ts";
import { buildRungStatuses } from "./rungs/coverage.ts";
import { analyzeStructure } from "./structure.ts";
import { analyzeTests } from "./test-analyzer.ts";
import type { Finding, ScanReport } from "./types.ts";
import { applyRepoConfig, isRuleDisabled, loadRepoConfig } from "./zero-defect/repo-config.ts";

export interface ScanOptions {
  configPath?: string;
  disableRules?: readonly string[];
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

  const applicableRungs = rungs.filter((r) => r.coverageGrade !== "not-applicable");
  const wellCoveredCount = applicableRungs.filter((r) => r.coverageGrade === "well-covered").length;
  const poorlyCoveredCount = applicableRungs.filter((r) => r.coverageGrade === "poorly-covered").length;
  const holeCount = applicableRungs.filter(
    (r) => r.coverageGrade === "not-covered" || r.coverageGrade === "over-budget",
  ).length;
  const unexecutedRungCount = applicableRungs.filter((r) => !r.executedInCi).length;
  const overallCoverageScore =
    applicableRungs.length > 0
      ? Math.round(applicableRungs.reduce((sum, r) => sum + r.coverageScore, 0) / applicableRungs.length)
      : 100;

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
      holeCount,
      poorlyCoveredCount,
      wellCoveredCount,
      applicableRungCount: applicableRungs.length,
      unexecutedRungCount,
      overallCoverageScore,
    },
    rungs,
    pushDownOpportunities: testResult.pushDownOpportunities,
    findings,
    missingLinters,
    testInventory: testResult.inventory,
  };
}
