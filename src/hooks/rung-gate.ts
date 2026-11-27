import fs from "node:fs";
import path from "node:path";
import type { DiscoveredRepo } from "../discover.ts";
import { buildRungStatuses } from "../rungs/coverage.ts";
import { isHostRepoFile } from "../rungs/manifest.ts";
import { analyzeTests } from "../test-analyzer.ts";
import type { Finding, RungStatus } from "../types.ts";

export interface RungGateOptions {
  requireWellCovered?: boolean;
  respectRatchet?: boolean;
}

const RATCHET_CANDIDATE_PATHS = [
  ".verification/ratchet.json",
  ".vstack-ratchet.json",
  "ratchet.json",
];

export function hasBrownfieldRatchet(repoRoot: string): boolean {
  if (!repoRoot) return false;
  return RATCHET_CANDIDATE_PATHS.some((rel) => fs.existsSync(path.join(repoRoot, rel)));
}

function countHostSourceAndTests(repo: DiscoveredRepo): { sourceCount: number; testCount: number } {
  let sourceCount = 0;
  let testCount = 0;
  for (const file of repo.files) {
    if (!file.language || file.isStub || !isHostRepoFile(file.rel)) continue;
    if (file.isTest) testCount += 1;
    else sourceCount += 1;
  }
  return { sourceCount, testCount };
}

function appendPerRungFindings(
  rungs: readonly RungStatus[],
  requireWellCovered: boolean,
  findings: Finding[],
): void {
  if (!Array.isArray(rungs)) throw new Error("rungs must be an array.");
  for (const r of rungs) {
    if (r.coverageGrade === "not-applicable") continue;
    if (r.coverageGrade === "not-covered" || r.coverageGrade === "over-budget") {
      const gap = r.gaps[0] ?? r.idealCoverage;
      findings.push({
        id: `RUNG:${r.coverageGrade}:${r.rung}`,
        rule: r.coverageGrade === "over-budget" ? "rung-over-budget" : "rung-not-covered",
        category: "oracle-lock",
        rung: r.rung,
        severity: "error",
        file: ".verification/rungs.json",
        line: 1,
        message: `Applicable rung ${r.rung} (${r.name}) is ${r.coverageGrade.toUpperCase()} (${r.coverageScore}%): ${gap}`,
        fix: `${gap}. Wire ${r.rung} in .verification/rungs.json and CI, then pass 'vstack verify . --strict'.`,
      });
    } else if (requireWellCovered && (r.coverageGrade === "poorly-covered" || !r.executedInCi)) {
      const gap = r.gaps[0] ?? `Raise ${r.rung} coverage >= 80% and verify in CI/receipts`;
      findings.push({
        id: `RUNG:poorly-covered:${r.rung}`,
        rule: "rung-poorly-covered",
        category: "oracle-lock",
        rung: r.rung,
        severity: "error",
        file: ".verification/rungs.json",
        line: 1,
        message: `Applicable rung ${r.rung} (${r.name}) is ${r.coverageGrade.toUpperCase()} (${r.coverageScore}%, CI=${r.executedInCi ? "yes" : "no"}): ${gap}`,
        fix: `${gap}. Run 'vstack verify . --strict' until every applicable rung is WELL-COVERED.`,
      });
    }
  }
}

export function auditRungCoverageFindings(
  repo: DiscoveredRepo,
  rungs: readonly RungStatus[],
  options: RungGateOptions = {},
): Finding[] {
  if (!repo.root) throw new Error("DiscoveredRepo.root is required.");
  if (options.respectRatchet && hasBrownfieldRatchet(repo.root)) return [];
  const { sourceCount, testCount } = countHostSourceAndTests(repo);
  if (sourceCount === 0) return [];

  const findings: Finding[] = [];
  if (!repo.manifest && !repo.manifestError) {
    findings.push({
      id: "RUNG:manifest-missing:.verification/rungs.json",
      rule: "rung-manifest-missing",
      category: "oracle-lock",
      rung: "R0",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: `Repository has ${sourceCount} production file(s) but no .verification/rungs.json manifest declaring applicable rungs.`,
      fix: "Run 'vstack init .' or create .verification/rungs.json declaring every applicable rung (including R2 with canary.enabled: true).",
    });
  }

  if (testCount === 0) {
    findings.push({
      id: "RUNG:zero-tests:repo",
      rule: "zero-tests-in-repo",
      category: "oracle-lock",
      rung: "R2",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: `Repository has ${sourceCount} production file(s) and 0 test files — tests are mandatory before finishing.`,
      fix: "Write real behavioral tests (R2 unit tables + PBT, R3 boundary/MBT, and higher rungs per archetype) and prove them with 'vstack verify . --strict'.",
    });
  }

  if (options.requireWellCovered && repo.manifest && !repo.manifest.rungs.R2) {
    findings.push({
      id: "RUNG:r2-undeclared:.verification/rungs.json",
      rule: "rung-r2-undeclared",
      category: "oracle-lock",
      rung: "R2",
      severity: "error",
      file: ".verification/rungs.json",
      line: 1,
      message: ".verification/rungs.json omits required rung R2 (pure unit tests + planted-fault canary).",
      fix: "Declare rungs.R2 with canary.enabled: true in .verification/rungs.json.",
    });
  }

  appendPerRungFindings(rungs, Boolean(options.requireWellCovered), findings);
  return findings;
}

export function evaluateGreenfieldRungGate(repo: DiscoveredRepo): Finding[] {
  if (!repo.root) throw new Error("DiscoveredRepo.root is required.");
  if (hasBrownfieldRatchet(repo.root)) return [];
  const { sourceCount } = countHostSourceAndTests(repo);
  if (sourceCount === 0) return [];
  const testResult = analyzeTests(repo);
  const rungs = buildRungStatuses(repo, testResult.inventory, { requireReceipts: false });
  return auditRungCoverageFindings(repo, rungs, { requireWellCovered: false, respectRatchet: true });
}
