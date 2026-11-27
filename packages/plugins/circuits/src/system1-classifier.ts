import { createHash } from "node:crypto";
import path from "node:path";
import { getCoreServices, type DiscoveredRepo, type ScannedFile  } from "@veristack/plugin";
import { analyzeTests } from "@veristack/plugin-anti-slop";
import { hasNonFrameworkImport, maskStrings } from "@veristack/plugin";
import type {
  System1CandidateFacts,
  System1ClassificationReport,
  System1Judgment,
  System1ModelAnswer,
  System1Request,
  System1RubricId,
  TestBoundary,
} from "@veristack/plugin";

export const SYSTEM1_RUBRIC_VERSION = "system1-improvements-v1";

export const SYSTEM1_RELEASE_BAR = {
  minPrecision: 0.95,
  minRecall: 0.8,
  minDecisionCoverage: 0.8,
  minPositivesPerRubric: 20,
  minNegativesPerRubric: 20,
} as const;

interface RubricDef {
  question: string;
  choices: readonly string[];
  kind: "test" | "instruction";
}

export const SYSTEM1_RUBRICS: Record<System1RubricId, RubricDef> = {
  "test-value": {
    question: "Based on the static facts and code, what best describes this test's behavioral value?",
    choices: ["BEHAVIOR", "CHANGE_DETECTOR", "TAUTOLOGY", "COVERAGE_FARM", "STRUCTURAL_GUARD", "INSUFFICIENT_CONTEXT"],
    kind: "test",
  },
  "test-boundary": {
    question: "Which execution boundary is demonstrated by these verified static facts?",
    choices: ["unit", "component", "host", "contract", "integration", "mbt", "e2e", "unknown"],
    kind: "test",
  },
  "push-down-eligibility": {
    question: "Can this test be pushed down to a faster verification rung without losing the failure mechanism?",
    choices: [
      "push_to_r0_r1_type_or_lint",
      "push_to_r2_table_or_pbt",
      "push_to_r3_mbt_or_component",
      "keep_at_current_rung",
      "forbidden_push_down",
      "insufficient_context",
    ],
    kind: "test",
  },
  "assertion-independence": {
    question: "Are the test's expected values derived independently of the implementation under test?",
    choices: ["independent_oracle", "self_derived_or_circular", "literal_only_tautology", "insufficient_context"],
    kind: "test",
  },
  "mock-boundary": {
    question: "How does this test substitute dependencies relative to module boundaries?",
    choices: ["real_dependencies", "strict_edge_double", "internal_overmocking", "insufficient_context"],
    kind: "test",
  },
  "instruction-to-lint": {
    question: "Does this agent instruction contain mechanical rules promotable to a deterministic linter?",
    choices: ["promotable_deterministic_rule", "already_enforced", "non_mechanical_guidance", "conflicting_rule", "insufficient_context"],
    kind: "instruction",
  },
  "change-risk-tier": {
    question: "Given the file's boundary and failure blast radius, which review tier fits changes here?",
    choices: ["low_auto_merge", "medium_single_review", "high_two_review_or_canary", "insufficient_context"],
    kind: "test",
  },
  "perf-architecture": {
    question: "Given verified complexity facts and hotspot code, which optimization family applies best?",
    choices: [
      "algorithmic_complexity",
      "data_layout_locality",
      "batch_or_index_io",
      "bounded_memory_streaming",
      "no_change_needed",
      "insufficient_context",
    ],
    kind: "test",
  },
};

export const SYSTEM1_RUBRIC_HASH = createHash("sha256")
  .update(JSON.stringify(SYSTEM1_RUBRICS))
  .digest("hex")
  .slice(0, 16);

const MAX_SNIPPET_CHARS = 1800;
const COMPONENT_ROOTS = new Set(["apps", "packages", "tests", "test", "services", "src", "tools", "skills"]);
const INSTRUCTION_FILE = /(?:^|\/)(?:AGENTS|CLAUDE|GEMINI|SKILL)\.md$/i;
const COVERAGE_FARM = /(?:^|[-_.])(?:coverage-|closeout|easy-?wins|zero-?coverage|leftovers)/i;
const LITERAL_EXPECT =
  /\bexpect\s*\(\s*(?:true|false|\d+|"[^"]*"|'[^']*')\s*\)\s*\.(?:toBe|toEqual|toStrictEqual)\s*\(\s*(?:true|false|\d+|"[^"]*"|'[^']*')\s*\)|\bAssert\.(?:Equal|StrictEqual|AreEqual)\s*\(\s*(?:true|false|\d+|"[^"]*")\s*,\s*(?:true|false|\d+|"[^"]*")\s*\)|\bassert_eq!\s*\(\s*(?:true|false|\d+|"[^"]*")\s*,\s*(?:true|false|\d+|"[^"]*")\s*\)|^\s*assert\s+(?:True|False|\d+)\s*(?:==\s*(?:True|False|\d+))?\s*$/m;
const SELF_DERIVED =
  /\bexpect\(\s*([A-Za-z_$][A-Za-z0-9_$.]*\([^()\n]{1,60}\))\s*\)\s*\.(?:toBe|toEqual|toStrictEqual)\(\s*\1\s*\)|\bAssert\.(?:Equal|StrictEqual|AreEqual)\(\s*([A-Za-z_][A-Za-z0-9_.]*\([^()\n]{1,60}\))\s*,\s*\2\s*\)|\bassert_eq!\(\s*([A-Za-z_][A-Za-z0-9_.:]*\([^()\n]{1,60}\))\s*,\s*\3\s*\)|\bassert\s+([A-Za-z_][A-Za-z0-9_.]*\([^()\n]{1,60}\))\s*==\s*\4(?=\s|$|#)/m;
const MULTI_STATUS =
  /\bexpect\s*\(\s*\[\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}[^\]]*\]\s*\)\s*\.(?:toContain|toContainEqual)|\.\s*toBeOneOf\s*\(\s*\[\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}|\[\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}[^\]]*\]\.(?:includes|contains)\s*\(|\bAssert\.Contains\s*\([^;\n]*HttpStatusCode\.\w+[^;\n]*HttpStatusCode\.\w+|\bstatus_code\s+in\s*(?:\(|\[|\{)\s*[1-5]\d{2}\s*,\s*[1-5]\d{2}/g;
const MOCK_CALL =
  /\b(?:vi|jest)\.mock\s*\(|\bvi\.fn\s*\(|\bnew\s+Mock\s*<|\bSubstitute\.For\s*[<(]|\bA\.Fake\s*<|\bMock[A-Z][A-Za-z0-9_]*::new\s*\(|\b(?:unittest\.mock\.)?patch(?:\.object)?\s*\(|\b(?:MagicMock|AsyncMock)\s*\(/g;
const NONDET =
  /\bMath\.random\s*\(|\bDate\.now\s*\(\s*\)|\bnew\s+Date\s*\(\s*\)|\bDateTime(?:Offset)?\.(?:Now|UtcNow)\b|\bnew\s+Random\s*\(\s*\)|\bRandom\.Shared\b|\bSystemTime::now\s*\(|\b(?:Utc|Local)::now\s*\(|\brand::(?:random|thread_rng|rng)\s*\(|\bdatetime\.(?:utc)?now\s*\(|\brandom\.(?:random|randint|choice)\s*\(|\btime\.time\s*\(\s*\)/g;
const PROMOTABLE_RULE = /\b(?:never|must not|do not|ban|forbid)\s+(?:use|call|import|add|commit)\b/i;

function componentOf(rel: string): string {
  const parts = rel.split("/").filter(Boolean);
  if (parts.length <= 1) return ".";
  if (COMPONENT_ROOTS.has(parts[0] ?? "") && parts.length >= 3) return `${parts[0]}/${parts[1]}`;
  return parts[0] ?? ".";
}

function selectRoundRobin<T extends { component: string; file: string }>(
  items: readonly T[],
  maxCandidates: number,
): { selected: T[]; distribution: Array<{ component: string; total: number; selected: number }> } {
  const byComp = new Map<string, T[]>();
  for (const item of [...items].sort((a, b) => a.file.localeCompare(b.file))) {
    const list = byComp.get(item.component) ?? [];
    list.push(item);
    byComp.set(item.component, list);
  }
  const queues = [...byComp.entries()].sort(([a], [b]) => a.localeCompare(b));
  const selected: T[] = [];
  const selectedCount = new Map<string, number>();

  for (let round = 0; selected.length < maxCandidates && queues.some(([, list]) => round < list.length); round++) {
    for (const [comp, list] of queues) {
      if (selected.length >= maxCandidates) break;
      const item = list[round];
      if (!item) continue;
      selected.push(item);
      selectedCount.set(comp, (selectedCount.get(comp) ?? 0) + 1);
    }
  }

  const distribution = queues.map(([component, list]) => ({
    component,
    total: list.length,
    selected: selectedCount.get(component) ?? 0,
  }));

  return { selected, distribution };
}

interface TestFactsInput {
  file: ScannedFile;
  ordinal: number;
  boundary: TestBoundary;
  testCaseCount: number;
  hasTableOrPbt: boolean;
  networkMock: boolean;
}

function buildTestFacts(input: TestFactsInput): System1CandidateFacts {
  const { file, ordinal, boundary, testCaseCount, hasTableOrPbt, networkMock } = input;
  if (!file.rel) throw new Error("Test file relative path is required.");
  if (ordinal < 1) throw new Error("Candidate ordinal must be >= 1.");
  const code = maskStrings(file.content);
  const hasSutImport = hasNonFrameworkImport(file.content, file.language);
  const coverageFarmName = COVERAGE_FARM.test(path.posix.basename(file.rel));
  const literalOnlyAssertion = LITERAL_EXPECT.test(file.content);
  const selfDerivedExpectation = SELF_DERIVED.test(code);
  const multiStatusCount = code.match(MULTI_STATUS)?.length ?? 0;
  const mockCount = code.match(MOCK_CALL)?.length ?? 0;
  const nondeterminismCount = code.match(NONDET)?.length ?? 0;
  const context: "complete" | "incomplete" = file.content.length <= MAX_SNIPPET_CHARS ? "complete" : "incomplete";

  const summaryParts = [
    `boundary=${boundary}`, `cases=${testCaseCount}`, `lines=${file.lines}`, `sutImport=${hasSutImport}`,
    `mocks=${mockCount}`, `networkMock=${networkMock}`, `tableOrPbt=${hasTableOrPbt}`,
    `literalOnly=${literalOnlyAssertion}`, `selfDerived=${selfDerivedExpectation}`,
    `multiStatus=${multiStatusCount}`, `nondet=${nondeterminismCount}`,
    `coverageFarm=${coverageFarmName}`, `context=${context}`,
  ];

  return {
    id: `s1-${String(ordinal).padStart(3, "0")}`, component: componentOf(file.rel), file: file.rel,
    kind: "test", context, lines: file.lines, testCaseCount, observedBoundary: boundary, hasSutImport,
    coverageFarmName, literalOnlyAssertion, selfDerivedExpectation, multiStatusCount, mockCount,
    networkMock, nondeterminismCount, hasTableOrPbt, factSummary: summaryParts.join("; "),
  };
}

function buildInstructionFacts(file: ScannedFile, ordinal: number): System1CandidateFacts {
  const hasPromotable = PROMOTABLE_RULE.test(file.content);
  const context: "complete" | "incomplete" = file.content.length <= MAX_SNIPPET_CHARS ? "complete" : "incomplete";
  return {
    id: `s1-${String(ordinal).padStart(3, "0")}`,
    component: componentOf(file.rel),
    file: file.rel,
    kind: "instruction",
    context,
    lines: file.lines,
    testCaseCount: 0,
    observedBoundary: "unknown",
    hasSutImport: false,
    coverageFarmName: false,
    literalOnlyAssertion: false,
    selfDerivedExpectation: false,
    multiStatusCount: 0,
    mockCount: 0,
    networkMock: false,
    nondeterminismCount: 0,
    hasTableOrPbt: false,
    factSummary: `kind=instruction; lines=${file.lines}; promotableRuleSignal=${hasPromotable}; context=${context}`,
  };
}

function staticLabelFor(facts: System1CandidateFacts, rubricId: System1RubricId, rawText: string): { label: string; isIssue: boolean; reason: string } {
  if (facts.context === "incomplete" && (rubricId === "test-value" || rubricId === "assertion-independence")) {
    return { label: "INSUFFICIENT_CONTEXT", isIssue: false, reason: "Snippet exceeds single-window limit; abstaining instead of truncating." };
  }

  if (rubricId === "test-value") {
    if (facts.coverageFarmName) return { label: "COVERAGE_FARM", isIssue: true, reason: "File is named for coverage padding rather than observable behavior." };
    if (facts.literalOnlyAssertion || facts.selfDerivedExpectation) return { label: "TAUTOLOGY", isIssue: true, reason: "Static facts show literal-only or self-derived equality assertion." };
    if (facts.mockCount >= 3 && facts.observedBoundary === "unit") return { label: "CHANGE_DETECTOR", isIssue: true, reason: "Heavy test-double count couples unit test to internal call choreography." };
    if (facts.hasSutImport && facts.testCaseCount > 0) return { label: "BEHAVIOR", isIssue: false, reason: "Imports production unit and asserts behavior without static tautology signals." };
    return { label: "INSUFFICIENT_CONTEXT", isIssue: false, reason: "No static production import established." };
  }

  if (rubricId === "test-boundary") {
    return { label: facts.observedBoundary, isIssue: false, reason: `Observed static boundary: ${facts.observedBoundary}.` };
  }

  if (rubricId === "push-down-eligibility") {
    if (facts.observedBoundary === "e2e" && facts.networkMock) {
      return { label: "push_to_r3_mbt_or_component", isIssue: true, reason: "E2E mocks backend network; push down to R3 Component UI + strict MSW." };
    }
    if (facts.observedBoundary === "e2e" && facts.testCaseCount >= 5) {
      return { label: "push_to_r2_table_or_pbt", isIssue: true, reason: "Combinatorial E2E matrix belongs in R2 Tests-as-Data tables." };
    }
    if (facts.observedBoundary === "unit" && !facts.hasTableOrPbt && facts.testCaseCount >= 8 && facts.lines > 200) {
      return { label: "push_to_r2_table_or_pbt", isIssue: true, reason: "Repetitive example-based unit suite can collapse into R2 table or PBT." };
    }
    if (facts.observedBoundary === "integration") {
      return { label: "forbidden_push_down", isIssue: false, reason: "Real engine / emulator boundary: never mock below R4 if verifying DB/rules/DLQ." };
    }
    return { label: "keep_at_current_rung", isIssue: false, reason: "Boundary aligns with current rung budget." };
  }

  if (rubricId === "assertion-independence") {
    if (facts.selfDerivedExpectation) return { label: "self_derived_or_circular", isIssue: true, reason: "Expected and actual repeat the same function call." };
    if (facts.literalOnlyAssertion) return { label: "literal_only_tautology", isIssue: true, reason: "Assertion compares only literals without exercising production code." };
    if (facts.multiStatusCount > 0) return { label: "self_derived_or_circular", isIssue: true, reason: "Multi-status assertion passes for both success and error responses." };
    return { label: "independent_oracle", isIssue: false, reason: "No static self-derived or literal-only assertion detected." };
  }

  if (rubricId === "mock-boundary") {
    if (facts.mockCount >= 3) return { label: "internal_overmocking", isIssue: true, reason: `${facts.mockCount} test doubles detected in one file.` };
    if (facts.networkMock) return { label: "strict_edge_double", isIssue: false, reason: "Substitutes only at network boundary." };
    return { label: "real_dependencies", isIssue: false, reason: "No module mocks or heavy test doubles detected." };
  }

  if (rubricId === "instruction-to-lint") {
    if (PROMOTABLE_RULE.test(rawText)) {
      return { label: "promotable_deterministic_rule", isIssue: true, reason: "Instruction states a mechanical ban/prohibition candidate for Oxlint/Roslyn." };
    }
    return { label: "non_mechanical_guidance", isIssue: false, reason: "No mechanical ban pattern detected in instruction text." };
  }

  const highRisk = /(?:auth|security|billing|payment|migration|permission|firestore-rules|prod|canary)/i.test(facts.file);
  if (highRisk) {
    return { label: "high_two_review_or_canary", isIssue: false, reason: "Touches auth/security/billing/migration/production path." };
  }
  return { label: facts.observedBoundary === "unit" ? "low_auto_merge" : "medium_single_review", isIssue: false, reason: "Standard risk tier based on path and boundary." };
}

function buildRequestsAndJudgments(
  selected: readonly System1CandidateFacts[],
  rawByFile: ReadonlyMap<string, string>,
  activeRubrics: readonly System1RubricId[],
): { requests: System1Request[]; judgments: System1Judgment[] } {
  const requests: System1Request[] = [];
  const judgments: System1Judgment[] = [];
  if (selected.length === 0) return { requests, judgments };
  if (activeRubrics.length === 0) return { requests, judgments };
  for (const cand of selected) {
    const raw = rawByFile.get(cand.file) ?? "";
    const snippet = raw.length <= MAX_SNIPPET_CHARS ? raw : `${raw.slice(0, MAX_SNIPPET_CHARS)}\n[TRUNCATED: ABSTAIN ON INCOMPLETE CONTEXT]`;
    for (const rubricId of activeRubrics) {
      const def = SYSTEM1_RUBRICS[rubricId];
      if (def.kind !== cand.kind) continue;
      requests.push({ id: `${cand.id}:${rubricId}`, candidateId: cand.id, rubricId, question: def.question, choices: def.choices, factContext: cand.factSummary, snippet });
      const stat = staticLabelFor(cand, rubricId, raw);
      const abstained = stat.label === "INSUFFICIENT_CONTEXT" || stat.label === "insufficient_context";
      judgments.push({
        candidateId: cand.id, file: cand.file, component: cand.component, rubricId,
        staticLabel: stat.label, modelChoice: null, modelScore: null,
        verdict: abstained ? "abstained" : "static_advisory", reason: stat.reason, humanReviewRequired: true,
      });
    }
  }
  return { requests, judgments };
}

export function buildSystem1Packet(
  repoOrPath: string | DiscoveredRepo,
  options: { maxCandidates?: number; rubrics?: readonly System1RubricId[] } = {},
): System1ClassificationReport {
  if (!repoOrPath) throw new Error("Repository path or object is required.");
  const repo = typeof repoOrPath === "string" ? (getCoreServices().discoverRepo ?? (() => { throw new Error("Core discoverRepo service not registered."); }))(repoOrPath) : repoOrPath;
  if (!repo.root) throw new Error("Discovered repository root is required.");
  const maxCandidates = Math.max(1, Math.min(100, options.maxCandidates ?? 30));
  const activeRubrics: readonly System1RubricId[] = options.rubrics ?? [
    "test-value", "test-boundary", "push-down-eligibility", "assertion-independence", "mock-boundary", "instruction-to-lint",
  ];
  const analysis = analyzeTests(repo);
  const invByFile = new Map(analysis.inventory.map((r) => [r.file, r]));
  const rawByFile = new Map(repo.files.map((f) => [f.rel, f.content]));
  const eligible: System1CandidateFacts[] = [];
  let ordinal = 1;
  for (const file of repo.files) {
    if (file.isTest && file.language) {
      const rec = invByFile.get(file.rel);
      if (!rec) continue;
      eligible.push(buildTestFacts({ file, ordinal: ordinal++, boundary: rec.boundary, testCaseCount: rec.testCaseCount, hasTableOrPbt: rec.hasTable || rec.hasPbt, networkMock: rec.hasNetworkMock }));
    } else if (INSTRUCTION_FILE.test(file.rel)) {
      eligible.push(buildInstructionFacts(file, ordinal++));
    }
  }
  const { selected, distribution } = selectRoundRobin(eligible, maxCandidates);
  const { requests, judgments } = buildRequestsAndJudgments(selected, rawByFile, activeRubrics);
  return {
    schemaVersion: 1, repo: repo.root, rubricVersion: SYSTEM1_RUBRIC_VERSION, rubricHash: SYSTEM1_RUBRIC_HASH,
    mode: "static-preclassify", calibrationStatus: "uncalibrated_advisory_only",
    scoreSemantics: "choice_concentration_not_calibrated_precision", releaseBar: { ...SYSTEM1_RELEASE_BAR },
    totalEligible: eligible.length, selectedCount: selected.length, truncated: eligible.length > selected.length,
    componentDistribution: distribution, candidates: selected, requests, judgments,
  };
}

export function corroborateSystem1Batch(
  packet: System1ClassificationReport,
  answers: readonly System1ModelAnswer[],
): System1ClassificationReport {
  const byId = new Map(answers.map((a) => [a.id, a]));
  const candById = new Map(packet.candidates.map((c) => [c.id, c]));
  const reqById = new Map(packet.requests.map((r) => [r.id, r]));

  const judgments: System1Judgment[] = packet.judgments.map((prior) => {
    const reqId = `${prior.candidateId}:${prior.rubricId}`;
    const ans = byId.get(reqId);
    const cand = candById.get(prior.candidateId);
    const req = reqById.get(reqId);

    if (!ans || !cand || !req || ans.abstained || cand.context === "incomplete") {
      return {
        ...prior,
        modelChoice: ans?.choice ?? null,
        modelScore: ans?.confidence ?? null,
        verdict: "abstained",
        reason: cand?.context === "incomplete"
          ? "Incomplete source context; System 1 classifier must abstain."
          : "Model abstained or omitted response.",
      };
    }

    if (!ans.choice || !req.choices.includes(ans.choice)) {
      return {
        ...prior,
        modelChoice: ans.choice,
        modelScore: ans.confidence,
        verdict: "disagreed_human_review",
        reason: "Model returned choice outside fixed rubric vocabulary.",
      };
    }

    if (ans.choice.toLowerCase() === prior.staticLabel.toLowerCase()) {
      const isIssue =
        prior.staticLabel === "COVERAGE_FARM" ||
        prior.staticLabel === "TAUTOLOGY" ||
        prior.staticLabel === "CHANGE_DETECTOR" ||
        prior.staticLabel === "self_derived_or_circular" ||
        prior.staticLabel === "literal_only_tautology" ||
        prior.staticLabel === "internal_overmocking" ||
        prior.staticLabel === "promotable_deterministic_rule" ||
        prior.staticLabel.startsWith("push_to_");

      return {
        ...prior,
        modelChoice: ans.choice,
        modelScore: ans.confidence,
        verdict: isIssue ? "corroborated_issue" : "corroborated_clear",
        reason: `Model corroborated static fact (${prior.staticLabel}). Advisory until rubric passes holdout bar.`,
      };
    }

    return {
      ...prior,
      modelChoice: ans.choice,
      modelScore: ans.confidence,
      verdict: "disagreed_human_review",
      reason: `Disagreement: static=${prior.staticLabel} vs model=${ans.choice}. Model never overrides static facts.`,
    };
  });

  return {
    ...packet,
    mode: "corroborated-system1",
    judgments,
  };
}
