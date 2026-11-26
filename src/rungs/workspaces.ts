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
  findings: readonly { file: string; severity: string }[] = [],
): WorkspaceLadderSummary[] {
  const workspaces = discoverWorkspaces(repo, repo.manifest);
  if (workspaces.length === 0) return [];
  const stemCounts = new Map<string, number>();
  for (const ws of workspaces) {
    const stem = ws.path.split("/").pop()?.toLowerCase() ?? "";
    if (stem) stemCounts.set(stem, (stemCounts.get(stem) ?? 0) + 1);
  }
  return workspaces.map((ws) => {
    const prefix = `${ws.path}/`;
    const childPrefixes = workspaces
      .filter((other) => other.path !== ws.path && other.path.startsWith(prefix))
      .map((other) => `${other.path}/`);
    const belongsToWs = (rel: string): boolean =>
      rel.startsWith(prefix) && !childPrefixes.some((cp) => rel.startsWith(cp));

    const wsStem = ws.path.split("/").pop()?.toLowerCase() ?? "";
    const wsRelLower = ws.path.toLowerCase();
    const wsShortStem = wsStem.includes("_") ? (wsStem.split("_").pop() ?? "") : "";
    const isUniqueStem = wsStem.length > 0 && (stemCounts.get(wsStem) ?? 0) === 1;
    const externalTestPrefixes = new Set<string>();
    for (const f of repo.files) {
      if (f.rel.endsWith(".csproj") && !belongsToWs(f.rel) && f.content.includes(`${ws.path.split("/").pop()}.csproj`)) {
        externalTestPrefixes.add(`${f.rel.slice(0, f.rel.lastIndexOf("/") + 1)}`);
      }
    }
    const matchesWsTest = (rel: string): boolean => {
      if (belongsToWs(rel)) return true;
      for (const ep of externalTestPrefixes) if (rel.startsWith(ep)) return true;
      const lowerRel = rel.toLowerCase();
      if (lowerRel.startsWith(`tests/${wsRelLower}/`) || lowerRel.startsWith(`test/${wsRelLower}/`)) return true;
      if (isUniqueStem && (lowerRel.startsWith(`tests/${wsStem}/`) || lowerRel.includes(`/tests/${wsStem}/`) || lowerRel.startsWith(`test/${wsStem}/`) || lowerRel.includes(`/test/${wsStem}/`) || lowerRel === `tests/test_${wsStem}.py` || lowerRel.endsWith(`/test_${wsStem}.py`))) return true;
      if (wsShortStem.length >= 4 && (lowerRel.startsWith(`tests/${wsShortStem}/`) || lowerRel === `tests/test_${wsShortStem}.py`)) return true;
      return false;
    };

    const subProd = repo.files.filter((f) => f.language && !f.isTest && belongsToWs(f.rel));
    const subInv = inventory.filter((t) => matchesWsTest(t.file));
    const subErrors = findings.filter((f) => f.severity === "error" && belongsToWs(f.file)).length;
    const highRiskFiles = subProd.filter((f) => HIGH_RISK_PATH.test(f.rel)).length;
    const subR2 = subInv.filter((t) => t.rung === "R2").length;
    const subR3 = subInv.filter((t) => t.rung === "R3").length;
    const subR4 = subInv.filter((t) => t.rung === "R4").length;
    const subR7 = subInv.filter((t) => t.rung === "R7").length;
    const needsR4 = ws.archetype === "service" || ws.archetype === "fullstack";
    const needsR7 = ws.archetype !== "library";
    const checks = [subR2 > 0, subR3 > 0, ...(needsR4 ? [subR4 > 0] : []), ...(needsR7 ? [subR7 > 0] : [])];
    const wellCoveredCount = checks.filter(Boolean).length;
    let score = Math.round((wellCoveredCount / Math.max(1, checks.length)) * 100);
    if (subErrors > 0) score = Math.min(score, 50);
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
