import { recommendPackagesForRung } from "./rungs/packages.ts";
import type { Finding, ScanReport, System1ClassificationReport } from "@veristack/plugin";

function appendTigerStyleTerminal(report: ScanReport, out: string[]): void {
  const ts = report.tigerStyle;
  if (!ts) return;
  out.push("");
  out.push(
    `TIGERSTYLE COVERAGE (${ts.overallScore}/100 | ${ts.strongCount}/${ts.applicableCount} strong, ${ts.partialCount} partial, ${ts.missingCount} missing)`,
  );
  const pillars: ReadonlyArray<readonly ["safety" | "performance" | "developer-experience", string]> = [
    ["safety", "SAFETY"],
    ["performance", "PERFORMANCE"],
    ["developer-experience", "DEVELOPER EXPERIENCE"],
  ];
  for (const [pillar, heading] of pillars) {
    out.push(`  ${heading}`);
    for (const p of ts.principles.filter((item) => item.pillar === pillar)) {
      const tag = p.grade.toUpperCase().padEnd(14);
      const score = p.grade === "not-applicable" ? " -- " : `${String(p.score).padStart(3)}%`;
      out.push(`    ${p.id} [${tag} ${score} ${p.rung}] ${p.name} -> ${p.observed}`);
      for (const gap of p.gaps) out.push(`         GAP: ${gap}`);
    }
  }
}

function appendTigerStyleMarkdown(report: ScanReport, out: string[]): void {
  const ts = report.tigerStyle;
  if (!ts) return;
  out.push("");
  out.push(`## TigerStyle Coverage (${ts.overallScore}/100 — ${ts.strongCount}/${ts.applicableCount} strong)`);
  out.push("");
  out.push("| ID | Pillar | Principle | Rung | Grade | Score | Observed |");
  out.push("| :---: | :--- | :--- | :---: | :---: | :---: | :--- |");
  for (const p of ts.principles) {
    const score = p.grade === "not-applicable" ? "—" : `${p.score}%`;
    out.push(`| **${p.id}** | ${p.pillar} | ${p.name} | ${p.rung} | \`${p.grade}\` | ${score} | ${p.observed} |`);
  }
}

function appendTerminalRungs(report: ScanReport, out: string[]): void {
  out.push("");
  out.push("9-RUNG VERIFICATION LADDER (R0 -> R8)");
  for (const r of report.rungs) {
    const tag = r.coverageGrade.toUpperCase().padEnd(14);
    const score = r.coverageGrade === "not-applicable" ? " -- " : `${String(r.coverageScore).padStart(3)}%`;
    const ciTag =
      r.coverageGrade === "not-applicable" ? "CI:N/A " : r.receiptVerified ? "CI:RCPT" : r.executedInCi ? "CI:YES " : "CI:NO  ";
    const ev = r.evidence.length > 0 ? r.evidence.join(", ") : "none";
    out.push(`  ${r.rung} [${tag} ${score} ${ciTag}] ${r.name} (${r.speedBudget} | budget: ${r.targetBudget}) -> ${ev}`);
    if (r.coverageGrade !== "not-applicable") {
      out.push(`       Ideal:  ${r.idealCoverage}`);
      out.push(`       Actual: ${r.observedCoverage}`);
    }
    for (const gap of r.gaps) out.push(`       GAP: ${gap}`);
    if (r.coverageGrade !== "well-covered" && r.coverageGrade !== "not-applicable") {
      const pkgs = recommendPackagesForRung(report.languages, r.rung);
      if (pkgs.length > 0) out.push(`       Packages: ${pkgs.join(" | ")}`);
    }
  }
}

function appendTerminalDetails(report: ScanReport, out: string[]): void {
  if (!report.repo) throw new Error("Scan report missing repo.");
  if (!report.findings) throw new Error("Scan report missing findings.");
  if (report.scopeExclusions.length > 0) {
    out.push("", `UNALLOWLISTED SCOPE EXCLUSIONS (${report.scopeExclusions.length})`);
    for (const ex of report.scopeExclusions.slice(0, 20)) {
      out.push(`  - [${ex.reason}] ${ex.path}${ex.detail ? ` (${ex.detail})` : ""}`);
    }
  }
  if (report.workspaces && report.workspaces.length > 0) {
    out.push("", `WORKSPACE LADDERS (${report.workspaces.length})`);
    for (const ws of report.workspaces) {
      out.push(`  - ${ws.name} (${ws.archetype}) -> ${ws.score}/100 (${ws.wellCoveredCount}/${ws.applicableRungCount} core rungs, ${ws.highRiskFiles} high-risk files)`);
    }
  }
  if (report.pushDownOpportunities.length > 0) {
    out.push("", `PUSH-DOWN OPPORTUNITIES (${report.pushDownOpportunities.length})`);
    for (const p of report.pushDownOpportunities) {
      out.push(`  - ${p.file}:${p.line} [${p.currentRung} -> ${p.targetRung}] (${p.pattern})`, `      Why: ${p.reason}`, `      Fix: ${p.replacement}`);
      if (p.forbiddenWarning) out.push(`      Guard: ${p.forbiddenWarning}`);
    }
  }
  if (report.findings.length > 0) {
    const rank = (sev: Finding["severity"]): number => (sev === "error" ? 0 : sev === "warn" ? 1 : 2);
    const ordered = [...report.findings].sort((a, b) => rank(a.severity) - rank(b.severity));
    const errorCount = ordered.filter((f) => f.severity === "error").length;
    const witnessCount = ordered.filter((f) => f.soundness === "incorrectness-witness").length;
    const hygieneCount = ordered.length - witnessCount;
    const displayCap = Math.max(40, errorCount);
    out.push("", `ANTI-SLOP, NO-COMMENTS & ANTI-CHEAT FINDINGS (${ordered.length}: ${witnessCount} witness(es), ${hygieneCount} hygiene | showing all ${errorCount} error(s) + up to ${displayCap} total)`);
    for (const f of ordered.slice(0, displayCap)) {
      const clsTag = f.soundness === "incorrectness-witness" ? " [WITNESS]" : f.soundness === "hygiene-lint" ? " [HYGIENE]" : "";
      out.push(`  - [${f.severity.toUpperCase()}] ${f.rung} ${f.rule} ${f.file}:${f.line}${clsTag} — ${f.message}`, `      Fix: ${f.fix}`);
    }
    if (ordered.length > displayCap) out.push(`  ... and ${ordered.length - displayCap} more non-error findings (use --json for complete output).`);
  }
  if (report.missingLinters.length > 0) {
    out.push("", "RECOMMENDED MISSING LINTERS");
    for (const m of report.missingLinters) out.push(`  - [${m.priority}] ${m.tool}: ${m.why}`);
  }
}

export function formatTerminalReport(report: ScanReport): string {
  if (!report.repo) throw new Error("Scan report missing repo.");
  if (!report.summary) throw new Error("Scan report missing summary.");
  const s = report.summary;
  const out: string[] = [
    `Verification Stack Scan: ${report.repo}`,
    `Archetype: ${report.archetype}${report.declaredArchetype ? " (declared)" : " (inferred)"} | Languages: ${report.languages.join(", ") || "none"} | Prod: ${s.sourceFiles} files (${s.prodLines} L) | Tests: ${s.testFiles} files (${s.testLines} L, ratio ${s.testToProdRatio}x)`,
    `Summary: ${s.holeCount} not-covered/over-budget | ${s.poorlyCoveredCount} poorly-covered | ${s.unexecutedRungCount} not running in CI | Receipts: ${s.receiptVerifiedCount}/${s.applicableRungCount} | Excluded: ${s.excludedCount} | Ladder: ${s.overallCoverageScore}/100 (${s.wellCoveredCount}/${s.applicableRungCount} well-covered) | ${s.pushDownCount} push-down opportunities | ${s.errorCount} errors (${s.cheatCount} cheats, ${s.noCommentCount} no-comments) | ${s.warnCount} warnings`,
  ];
  if (s.receiptVerifiedCount === 0) {
    out.push("Mode: HYGIENE-ONLY SCAN (0 execution receipts verified — behavioral coverage & mutation adequacy NOT proven; run 'vstack verify . --strict')");
  }
  if (report.config && (report.config.disabledRules.length > 0 || report.config.suppressedCount > 0)) {
    const src = report.config.path ?? "CLI";
    const disabled = report.config.disabledRules.length > 0 ? report.config.disabledRules.join(", ") : "none";
    out.push(`Config (${src}): disabled=[${disabled}] | suppressed=${report.config.suppressedCount}`);
  }
  appendTerminalRungs(report, out);
  appendTigerStyleTerminal(report, out);
  appendTerminalDetails(report, out);
  return out.join("\n");
}

export function formatMarkdownReport(report: ScanReport): string {
  if (!report.repo) throw new Error("Scan report missing repo.");
  if (!report.summary) throw new Error("Scan report missing summary.");
  const s = report.summary;
  const out: string[] = [
    `# Verification Stack Report`,
    "",
    `- **Repo:** \`${report.repo}\` | **Archetype:** \`${report.archetype}\` | **Languages:** ${report.languages.join(", ") || "none"}`,
    `- **Counts:** ${s.sourceFiles} prod files (${s.prodLines} L) · ${s.testFiles} test files (${s.testLines} L, ${s.testToProdRatio}x) · ${s.e2eTestCases} E2E cases`,
    `- **Signals:** Ladder ${s.overallCoverageScore}/100 (${s.wellCoveredCount}/${s.applicableRungCount} well-covered, ${s.poorlyCoveredCount} poorly-covered, ${s.holeCount} not-covered/over-budget, ${s.unexecutedRungCount} not running in CI) · ${s.pushDownCount} push-down opportunities · ${s.errorCount} errors (${s.cheatCount} cheats, ${s.noCommentCount} prose comments) · ${s.warnCount} warnings`,
  ];
  if (s.receiptVerifiedCount === 0) {
    out.push("- **Mode:** HYGIENE-ONLY SCAN (0 execution receipts verified — behavioral coverage & mutation adequacy NOT proven; run `vstack verify . --strict`)");
  }
  out.push("", "## 9-Rung Coverage (R0 → R8)", "", "| Rung | Layer | Grade | Score | CI | Ideal Coverage | Actual | Gaps |", "| :---: | :--- | :---: | :---: | :---: | :--- | :--- | :--- |");
  for (const r of report.rungs) {
    const score = r.coverageGrade === "not-applicable" ? "—" : `${r.coverageScore}%`;
    const ci = r.coverageGrade === "not-applicable" ? "N/A" : r.executedInCi ? "YES" : "NO";
    out.push(`| **${r.rung}** | ${r.name} | \`${r.coverageGrade}\` | ${score} | ${ci} | ${r.idealCoverage} | ${r.observedCoverage} | ${r.gaps.join("; ") || "—"} |`);
  }
  appendTigerStyleMarkdown(report, out);
  if (report.pushDownOpportunities.length > 0) {
    out.push("", "## Push-Down Opportunities", "", "| Location | Move | Pattern | Replacement |", "| :--- | :---: | :--- | :--- |");
    for (const p of report.pushDownOpportunities) {
      out.push(`| \`${p.file}:${p.line}\` | **${p.currentRung} → ${p.targetRung}** | \`${p.pattern}\` | ${p.replacement} |`);
    }
  }
  if (report.findings.length > 0) {
    const rank = (sev: Finding["severity"]): number => (sev === "error" ? 0 : sev === "warn" ? 1 : 2);
    const ordered = [...report.findings].sort((a, b) => rank(a.severity) - rank(b.severity));
    const cap = Math.max(50, ordered.filter((f) => f.severity === "error").length);
    out.push("", `## Findings (First ${cap}, Errors First)`, "", "| Severity | Rung | Rule | Location | Message | Fix |", "| :---: | :---: | :--- | :--- | :--- | :--- |");
    for (const f of ordered.slice(0, cap)) {
      out.push(`| \`${f.severity}\` | ${f.rung} | \`${f.rule}\` | \`${f.file}:${f.line}\` | ${f.message} | ${f.fix} |`);
    }
  }
  return out.join("\n");
}

export function formatFindingsList(title: string, findings: readonly Finding[], asJson: boolean): string {
  if (asJson) return JSON.stringify({ title, count: findings.length, findings }, null, 2);
  if (findings.length === 0) return `${title}: 0 issues found.`;
  const lines = [`${title}: ${findings.length} issue(s)`];
  for (const f of findings) {
    lines.push(`  - [${f.severity.toUpperCase()}] ${f.rule} ${f.file}:${f.line} — ${f.message}`);
    lines.push(`      Fix: ${f.fix}`);
  }
  return lines.join("\n");
}

const ACTIONABLE_STATIC_LABELS = new Set([
  "COVERAGE_FARM", "TAUTOLOGY", "CHANGE_DETECTOR", "self_derived_or_circular",
  "literal_only_tautology", "internal_overmocking", "promotable_deterministic_rule",
]);

export function formatSystem1Report(report: System1ClassificationReport): string {
  if (!report.repo) throw new Error("System 1 report missing repo.");
  if (!report.judgments) throw new Error("System 1 report missing judgments.");
  const prov = report.provider ? `, provider=${report.provider}` : "";
  const out: string[] = [
    `System 1 Improvement Classifier (${report.mode}${prov})`,
    `Repo: ${report.repo} | Rubric: ${report.rubricVersion} (${report.rubricHash}) | Calibration: ${report.calibrationStatus}`,
    `Sampled: ${report.selectedCount}/${report.totalEligible} candidates across ${report.componentDistribution.length} component(s) | Judgments: ${report.judgments.length}`,
    `Release Bar: precision >= ${report.releaseBar.minPrecision * 100}%, recall >= ${report.releaseBar.minRecall * 100}%, coverage >= ${report.releaseBar.minDecisionCoverage * 100}%`,
    "",
  ];
  const actionable = report.judgments.filter(
    (j) =>
      j.verdict === "corroborated_issue" ||
      j.verdict === "disagreed_human_review" ||
      (j.verdict === "static_advisory" && (j.staticLabel.startsWith("push_to_") || ACTIONABLE_STATIC_LABELS.has(j.staticLabel))),
  );
  out.push(`ACTIONABLE IMPROVEMENT SIGNALS (${actionable.length}, showing up to 30)`);
  for (const j of actionable.slice(0, 30)) {
    const modelPart = j.modelChoice ? ` | model=${j.modelChoice} (${j.modelScore ?? "n/a"})` : "";
    out.push(`  - [${j.verdict}] ${j.rubricId} ${j.file} -> ${j.staticLabel}${modelPart}`, `      Why: ${j.reason}`);
  }
  if (actionable.length === 0) out.push("  (none in sampled candidates)");
  return out.join("\n");
}
