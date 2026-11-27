import fs from "node:fs";
import path from "node:path";

const RUNG_IDS = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"] as const;
type RungKey = (typeof RUNG_IDS)[number];

export interface DossierWorkspace {
  path: string;
  role: string;
  archetype: string;
  hasOwnOrLinkedTests: boolean;
  testLocations: string[];
}

export interface DossierRung {
  applicable: boolean;
  configuredTools: Array<{ tool: string; citation: string }>;
  prBlockingCi: {
    executed: boolean;
    trustworthy: boolean;
    evasionHazard?: string;
    executionChain?: string;
  };
  independentDepth: string;
}

export interface GroundTruthDossier {
  auditorModel?: string;
  repo: string;
  commitSha: string;
  defaultBranch: string;
  archetype: { value: string; rationale?: string; citations: string[] };
  languages: { primary: string[]; auxiliary?: string[] };
  workspaces: DossierWorkspace[];
  rungs: Record<RungKey, DossierRung>;
}

interface ConsensusDossier {
  repo: string;
  commitSha: string;
  defaultBranch: string;
  panelModels: string[];
  archetype: { value: string; unanimous: boolean; citations: string[] };
  languages: { primary: string[] };
  workspaces: DossierWorkspace[];
  rungs: Record<RungKey, DossierRung>;
  disagreements: Array<Record<string, unknown>>;
}

interface MinimalScanReport {
  archetype: string;
  languages?: string[];
  workspaces?: Array<{ path: string; score: number }>;
  rungs?: Array<{ rung: string; coverageGrade: string; coverageScore: number; executedInCi: boolean }>;
  summary?: { overallCoverageScore?: number };
  findings?: Array<{ rule: string; file: string; line: number; severity: string; message: string }>;
}

function majorityVote<T>(values: readonly T[]): { winner: T | undefined; votes: number; total: number; unanimous: boolean } {
  const counts = new Map<T, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return { winner: ranked[0]?.[0], votes: ranked[0]?.[1] ?? 0, total: values.length, unanimous: ranked.length <= 1 };
}

export function validateDossier(dossier: GroundTruthDossier): string[] {
  const errors: string[] = [];
  if (!dossier.archetype?.value) errors.push("missing archetype.value");
  if (!Array.isArray(dossier.archetype?.citations) || dossier.archetype.citations.length === 0) {
    errors.push("archetype.citations must be non-empty");
  }
  for (const r of RUNG_IDS) {
    const entry = dossier.rungs?.[r];
    if (!entry) { errors.push(`missing rung ${r}`); continue; }
    if (typeof entry.applicable !== "boolean") errors.push(`${r}.applicable must be boolean`);
    if (typeof entry.prBlockingCi?.executed !== "boolean") errors.push(`${r}.prBlockingCi.executed must be boolean`);
    if (typeof entry.prBlockingCi?.trustworthy !== "boolean") errors.push(`${r}.prBlockingCi.trustworthy must be boolean`);
    if (entry.prBlockingCi?.executed && !entry.prBlockingCi?.executionChain) {
      errors.push(`${r}.prBlockingCi.executionChain required when executed=true`);
    }
  }
  return errors;
}

function mergeDossierWorkspaces(
  dossiers: readonly GroundTruthDossier[],
  threshold: number,
  disagreements: Array<Record<string, unknown>>,
): DossierWorkspace[] {
  if (dossiers.length === 0) return [];
  const wsByPath = new Map<string, DossierWorkspace[]>();
  for (const d of dossiers) {
    for (const ws of d.workspaces ?? []) {
      const list = wsByPath.get(ws.path) ?? [];
      list.push(ws);
      wsByPath.set(ws.path, list);
    }
  }
  const workspaces: DossierWorkspace[] = [];
  for (const [wsPath, items] of wsByPath.entries()) {
    if (items.length < threshold) continue;
    const roleVote = majorityVote(items.map((w) => w.role));
    const archWsVote = majorityVote(items.map((w) => w.archetype));
    const testedVote = majorityVote(items.map((w) => Boolean(w.hasOwnOrLinkedTests)));
    if (!roleVote.unanimous || !testedVote.unanimous) {
      disagreements.push({ field: `workspace:${wsPath}`, role: roleVote, tested: testedVote });
    }
    workspaces.push({
      path: wsPath,
      role: roleVote.winner ?? "product",
      archetype: archWsVote.winner ?? "library",
      hasOwnOrLinkedTests: Boolean(testedVote.winner),
      testLocations: [...new Set(items.flatMap((w) => w.testLocations ?? []))],
    });
  }
  return workspaces.sort((a, b) => a.path.localeCompare(b.path));
}

function mergeDossierRungs(
  dossiers: readonly GroundTruthDossier[],
  disagreements: Array<Record<string, unknown>>,
): Record<RungKey, DossierRung> {
  if (dossiers.length === 0) throw new Error("mergeDossierRungs requires dossiers");
  const rungs = {} as Record<RungKey, DossierRung>;
  for (const r of RUNG_IDS) {
    const entries = dossiers.map((d) => d.rungs[r]).filter((e): e is DossierRung => Boolean(e));
    const appVote = majorityVote(entries.map((e) => Boolean(e.applicable)));
    const execVote = majorityVote(entries.map((e) => Boolean(e.prBlockingCi?.executed)));
    const trustVote = majorityVote(entries.map((e) => Boolean(e.prBlockingCi?.trustworthy)));
    const depthVote = majorityVote(entries.map((e) => e.independentDepth ?? "none"));
    const anyExecuted = entries.some((e) => Boolean(e.prBlockingCi?.executed));
    if (!execVote.unanimous || (anyExecuted && !trustVote.unanimous) || !appVote.unanimous) {
      disagreements.push({
        field: `rung:${r}`,
        applicable: entries.map((e) => e.applicable),
        executed: entries.map((e) => e.prBlockingCi?.executed),
        trustworthy: entries.map((e) => e.prBlockingCi?.trustworthy),
      });
    }
    const toolMap = new Map<string, { tool: string; citation: string }>();
    for (const e of entries) {
      for (const t of e.configuredTools ?? []) {
        const key = t.tool.toLowerCase();
        if (key && !toolMap.has(key)) toolMap.set(key, t);
      }
    }
    let chain: string | undefined;
    let hazard: string | undefined;
    for (const e of entries) {
      if (!chain && e.prBlockingCi?.executionChain) chain = e.prBlockingCi.executionChain;
      if (!hazard && e.prBlockingCi?.evasionHazard) hazard = e.prBlockingCi.evasionHazard;
    }
    rungs[r] = {
      applicable: Boolean(appVote.winner),
      configuredTools: [...toolMap.values()],
      prBlockingCi: {
        executed: Boolean(execVote.winner),
        trustworthy: Boolean(trustVote.winner),
        ...(chain ? { executionChain: chain } : {}),
        ...(hazard ? { evasionHazard: hazard } : {}),
      },
      independentDepth: depthVote.winner ?? "none",
    };
  }
  return rungs;
}

export function mergeDossiers(dossiers: readonly GroundTruthDossier[]): ConsensusDossier {
  const first = dossiers[0];
  if (!first) throw new Error("mergeDossiers requires at least one dossier");
  const disagreements: Array<Record<string, unknown>> = [];
  const archVote = majorityVote(dossiers.map((d) => d.archetype.value));
  if (!archVote.unanimous) {
    disagreements.push({ field: "archetype", values: dossiers.map((d) => ({ model: d.auditorModel ?? "unknown", value: d.archetype.value })) });
  }
  const langCounts = new Map<string, number>();
  for (const d of dossiers) {
    for (const l of new Set(d.languages?.primary ?? [])) langCounts.set(l, (langCounts.get(l) ?? 0) + 1);
  }
  const threshold = Math.ceil(dossiers.length / 2);
  const primaryLanguages = [...langCounts.entries()].filter(([, c]) => c >= threshold).map(([l]) => l).sort();
  return {
    repo: first.repo,
    commitSha: first.commitSha,
    defaultBranch: first.defaultBranch,
    panelModels: dossiers.map((d) => d.auditorModel ?? "unknown"),
    archetype: {
      value: archVote.winner ?? "library",
      unanimous: archVote.unanimous,
      citations: [...new Set(dossiers.flatMap((d) => d.archetype?.citations ?? []))],
    },
    languages: { primary: primaryLanguages },
    workspaces: mergeDossierWorkspaces(dossiers, threshold, disagreements),
    rungs: mergeDossierRungs(dossiers, disagreements),
    disagreements,
  };
}

function diffWorkspaces(consensus: ConsensusDossier, vWorkspaces: ReadonlyArray<{ path: string; score: number }>) {
  const gtWsMap = new Map(consensus.workspaces.map((w) => [w.path, w]));
  const wsFalsePositives: Array<{ path: string; gtRole: string; vScore: number; triggersZeroCliff: boolean }> = [];
  const wsTestLinkFalseNegatives: Array<{ path: string; expectedTests: string[] }> = [];
  const wsTrueZeros: string[] = [];
  let wsMatchedProducts = 0;
  for (const vw of vWorkspaces) {
    const gt = gtWsMap.get(vw.path);
    if (gt && gt.role !== "product") {
      wsFalsePositives.push({ path: vw.path, gtRole: gt.role, vScore: vw.score, triggersZeroCliff: vw.score === 0 });
    } else if (gt && gt.role === "product") {
      wsMatchedProducts += 1;
      if (vw.score === 0 && gt.hasOwnOrLinkedTests) {
        wsTestLinkFalseNegatives.push({ path: vw.path, expectedTests: gt.testLocations });
      } else if (vw.score === 0 && !gt.hasOwnOrLinkedTests) {
        wsTrueZeros.push(vw.path);
      }
    }
  }
  return {
    gtProductCount: consensus.workspaces.filter((w) => w.role === "product").length,
    vCount: vWorkspaces.length,
    wsMatchedProducts,
    wsFalsePositives,
    wsTestLinkFalseNegatives,
    wsTrueZeros,
  };
}

function diffRungs(consensus: ConsensusDossier, scanReport: MinimalScanReport) {
  if (!consensus.rungs) throw new Error("consensus.rungs missing");
  const vRungs = new Map((scanReport.rungs ?? []).map((r) => [r.rung, r]));
  const ciFalseNegatives: Array<{ rung: RungKey; chain: string; tools: string[] }> = [];
  const ciFalsePositives: Array<{ rung: RungKey; gtExecuted: boolean; gtTrustworthy: boolean; hazard: string }> = [];
  const securityHolds: Array<{ rung: RungKey; hazard: string }> = [];
  const rungDiffs: Array<{ rung: RungKey; verdict: string; bucket: string; gtApplicable: boolean; vApplicable: boolean; gtCi: boolean; vCi: boolean; vScore: number; gtDepth: string }> = [];
  for (const r of RUNG_IDS) {
    const gt = consensus.rungs[r];
    const vr = vRungs.get(r);
    if (!gt || !vr) continue;
    const vExec = Boolean(vr.executedInCi);
    const gtExpectedCi = gt.applicable && gt.prBlockingCi.executed && gt.prBlockingCi.trustworthy;
    let verdict = "MATCH";
    let bucket = "OK";
    if (gtExpectedCi && !vExec) {
      verdict = "CI-FN";
      bucket = "A-BLIND-SPOT";
      ciFalseNegatives.push({ rung: r, chain: gt.prBlockingCi.executionChain ?? "unknown", tools: gt.configuredTools.map((t) => t.tool) });
    } else if (!gtExpectedCi && vExec) {
      verdict = "CI-FP";
      bucket = "P0-OVERCREDIT";
      ciFalsePositives.push({ rung: r, gtExecuted: gt.prBlockingCi.executed, gtTrustworthy: gt.prBlockingCi.trustworthy, hazard: gt.prBlockingCi.evasionHazard ?? "not executed in PR CI" });
    } else if (gt.applicable && gt.prBlockingCi.executed && !gt.prBlockingCi.trustworthy && !vExec) {
      verdict = "SECURITY-HOLD";
      bucket = "B-INTENTIONAL-LOCK";
      securityHolds.push({ rung: r, hazard: gt.prBlockingCi.evasionHazard ?? "untrustworthy CI" });
    }
    rungDiffs.push({
      rung: r, verdict, bucket, gtApplicable: gt.applicable, vApplicable: vr.coverageGrade !== "not-applicable",
      gtCi: gtExpectedCi, vCi: vExec, vScore: vr.coverageScore, gtDepth: gt.independentDepth,
    });
  }
  const ciTp = rungDiffs.filter((d) => d.gtCi && d.vCi).length;
  const ciPrecision = ciTp + ciFalsePositives.length > 0 ? ciTp / (ciTp + ciFalsePositives.length) : 1;
  const ciRecall = ciTp + ciFalseNegatives.length > 0 ? ciTp / (ciTp + ciFalseNegatives.length) : 1;
  return {
    ci: {
      truePositives: ciTp,
      falseNegatives: ciFalseNegatives,
      falsePositives: ciFalsePositives,
      securityHolds,
      precision: Number(ciPrecision.toFixed(3)),
      recall: Number(ciRecall.toFixed(3)),
    },
    rungDiffs,
  };
}

export function diffAgainstVeristack(consensus: ConsensusDossier, scanReport: MinimalScanReport) {
  if (!consensus.repo) throw new Error("consensus.repo is required");
  const gtLangs = new Set(consensus.languages.primary);
  const vLangs = new Set(scanReport.languages ?? []);
  const { ci, rungDiffs } = diffRungs(consensus, scanReport);
  return {
    repo: consensus.repo,
    commitSha: consensus.commitSha,
    archetype: { gt: consensus.archetype.value, veristack: scanReport.archetype, match: scanReport.archetype === consensus.archetype.value },
    languages: {
      gt: [...gtLangs],
      veristack: [...vLangs],
      phantomLanguages: [...vLangs].filter((l) => !gtLangs.has(l)),
      missingLanguages: [...gtLangs].filter((l) => !vLangs.has(l)),
    },
    workspaces: diffWorkspaces(consensus, scanReport.workspaces ?? []),
    ci,
    rungDiffs,
    panelDisagreements: consensus.disagreements,
    veristackScore: scanReport.summary?.overallCoverageScore ?? 0,
  };
}

export function sampleFindingsForAdjudication(repoRoot: string, scanReport: MinimalScanReport, perRule = 5, maxRules = 5) {
  const byRule = new Map<string, Array<{ rule: string; file: string; line: number; severity: string; message: string }>>();
  for (const f of scanReport.findings ?? []) {
    if (f.rule === "no-comments") continue;
    const list = byRule.get(f.rule) ?? [];
    list.push(f);
    byRule.set(f.rule, list);
  }
  const ranked = [...byRule.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, maxRules);
  return ranked.map(([rule, list]) => {
    const step = Math.max(1, Math.floor(list.length / perRule));
    const picked: Array<{ file: string; line: number; severity: string; message: string; excerpt: string }> = [];
    for (let i = 0; i < list.length && picked.length < perRule; i += step) {
      const f = list[i];
      if (!f) continue;
      let excerpt = "";
      try {
        const lines = fs.readFileSync(path.join(repoRoot, f.file), "utf8").split(/\r?\n/);
        const start = Math.max(0, (f.line ?? 1) - 6);
        const end = Math.min(lines.length, (f.line ?? 1) + 5);
        excerpt = lines.slice(start, end).map((l, idx) => `${start + idx + 1}: ${l}`).join("\n");
      } catch {
        excerpt = "<unreadable>";
      }
      picked.push({ file: f.file, line: f.line, severity: f.severity, message: f.message, excerpt });
    }
    return { rule, totalHits: list.length, samples: picked };
  });
}

export function aggregateScorecard(diffs: ReadonlyArray<ReturnType<typeof diffAgainstVeristack>>) {
  const n = Math.max(1, diffs.length);
  const archMatches = diffs.filter((d) => d.archetype.match).length;
  const ciTp = diffs.reduce((s, d) => s + d.ci.truePositives, 0);
  const ciFn = diffs.reduce((s, d) => s + d.ci.falseNegatives.length, 0);
  const ciFp = diffs.reduce((s, d) => s + d.ci.falsePositives.length, 0);
  const secHolds = diffs.reduce((s, d) => s + d.ci.securityHolds.length, 0);
  const wsFalseZeroCliffs = diffs.reduce((s, d) => s + d.workspaces.wsFalsePositives.filter((w) => w.triggersZeroCliff).length, 0);
  const wsLinkFns = diffs.reduce((s, d) => s + d.workspaces.wsTestLinkFalseNegatives.length, 0);
  return {
    reposAudited: diffs.length,
    archetypeAccuracy: Number((archMatches / n).toFixed(3)),
    ciPrecision: Number((ciTp + ciFp > 0 ? ciTp / (ciTp + ciFp) : 1).toFixed(3)),
    ciRecall: Number((ciTp + ciFn > 0 ? ciTp / (ciTp + ciFn) : 1).toFixed(3)),
    ciTruePositives: ciTp,
    ciFalseNegatives: ciFn,
    ciFalsePositives: ciFp,
    securityHolds: secHolds,
    wsFalseZeroCliffs,
    wsLinkFalseNegatives: wsLinkFns,
  };
}

if (import.meta.main) {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "diff" && rest.length >= 2) {
    const scanPath = rest[0] ?? "";
    const scanReport = JSON.parse(fs.readFileSync(scanPath, "utf8")) as MinimalScanReport;
    const dossiers = rest.slice(1).map((p) => JSON.parse(fs.readFileSync(p, "utf8")) as GroundTruthDossier);
    const consensus = mergeDossiers(dossiers);
    console.log(JSON.stringify(diffAgainstVeristack(consensus, scanReport), null, 2));
  } else {
    console.error("Usage: bun scripts/calibration/diff-dossier.ts diff <scan-report.json> <dossier1.json> [dossier2.json ...]");
    process.exit(1);
  }
}
