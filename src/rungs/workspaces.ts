import type { DiscoveredRepo } from "../discover.ts";
import type {
  RungCheck,
  RungCoverageGrade,
  RungId,
  RungStatus,
  TestFileRecord,
  WorkspaceLadderSummary,
} from "../types.ts";
import { discoverWorkspaces } from "./manifest.ts";

const HIGH_RISK_PATH =
  /(?:auth|billing|payment|money|crypto|security|session|token|permission|rbac|migration|ledger|state-machine|parser|receipt|ratchet)/i;

export interface RungBuilderInput {
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
  receiptVerified: boolean;
  adequacyKillRate?: number;
  notApplicable?: boolean;
  overBudget?: boolean;
  overBudgetPenaltyScore?: number;
}

export function finalizeRung(input: RungBuilderInput): RungStatus {
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
      receiptVerified: false,
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
    gaps.push(`Rung ${input.rung} has no verified CI execution / HEAD receipt — run 'vstack run-rung ${input.rung}' in PR-blocking CI`);
    score = Math.min(score, 50);
  } else if (!input.executedInCi && input.evidence.length === 0) {
    gaps.push(`Rung ${input.rung} is NOT executed in PR-blocking CI workflows`);
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
      receiptVerified: input.receiptVerified,
      adequacyKillRate: input.adequacyKillRate,
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
    receiptVerified: input.receiptVerified,
    adequacyKillRate: input.adequacyKillRate,
    idealCoverage: input.idealCoverage,
    observedCoverage: input.observedCoverage,
    checks: input.checks,
    observedCount: input.observedCount,
    evidence: input.evidence,
    gaps,
  };
}

export function buildWorkspaceLadders(
  repo: DiscoveredRepo,
  inventory: readonly TestFileRecord[],
): WorkspaceLadderSummary[] {
  const workspaces = discoverWorkspaces(repo, repo.manifest);
  if (workspaces.length === 0) return [];
  return workspaces.map((ws) => {
    const prefix = `${ws.path}/`;
    const subProd = repo.files.filter((f) => f.language && !f.isTest && f.rel.startsWith(prefix));
    const subInv = inventory.filter((t) => t.file.startsWith(prefix));
    const highRiskFiles = subProd.filter((f) => HIGH_RISK_PATH.test(f.rel)).length;
    const subR2 = subInv.filter((t) => t.rung === "R2").length;
    const subR3 = subInv.filter((t) => t.rung === "R3").length;
    const subR4 = subInv.filter((t) => t.rung === "R4").length;
    const subR7 = subInv.filter((t) => t.rung === "R7").length;
    const needsR4 = ws.archetype === "service" || ws.archetype === "fullstack";
    const needsR7 = ws.archetype !== "library";
    const checks = [subR2 > 0, subR3 > 0, ...(needsR4 ? [subR4 > 0] : []), ...(needsR7 ? [subR7 > 0] : [])];
    const wellCoveredCount = checks.filter(Boolean).length;
    const score = Math.round((wellCoveredCount / Math.max(1, checks.length)) * 100);
    return {
      name: ws.name,
      path: ws.path,
      archetype: ws.archetype,
      score,
      wellCoveredCount,
      applicableRungCount: checks.length,
      highRiskFiles,
    };
  });
}
