import type { CircuitMeta, System1CandidateFacts, System1Request } from "../types.ts";
import { resolveThreeBandDecision, type CircuitDefinition } from "./engine.ts";

export interface TestTriageInput {
  file: string;
  snippet: string;
  facts: System1CandidateFacts;
}

export interface PrRiskInput {
  file: string;
  addedLines: number;
  removedLines: number;
  diffSnippet: string;
  hasCheatHit: boolean;
}

export interface InstructionRuleInput {
  file: string;
  line: number;
  clause: string;
  alreadyEnforced: boolean;
  hasConflict: boolean;
}

export interface PerfAdvisorInput {
  file: string;
  lines: number;
  snippet: string;
  staticPerfHits: string[];
  timeExponent?: number;
  spaceExponent?: number;
}

const HIGH_RISK_PATH =
  /(?:^|\/)(?:\.github\/workflows\/|codeowners$|migrations\/|auth|security|billing|payment|permission|contracts\.lock)/i;
const DOC_OR_TEST_ONLY = /(?:\.md$|(?:^|\/)(?:tests?|__tests__)\/|\.(?:test|spec)\.[cm]?[jt]sx?$)/i;
const PROMOTABLE_MECHANICAL = /\b(?:never|must not|do not|ban|forbid)\s+(?:use|call|import|add|commit|skip|weaken)\b/i;

export const testTriageCircuit: CircuitDefinition<TestTriageInput, System1CandidateFacts> = {
  id: "test-triage",
  version: "1.0.0",
  title: "Test Value & Push-Down Circuit",
  description:
    "90% deterministic static pre-filter (coverage farms, tautologies, over-mocking, clean tables/PBTs) + 10% BYO System 1 judgment on ambiguous tests.",
  rubricId: "test-value",
  choices: ["BEHAVIOR", "CHANGE_DETECTOR", "TAUTOLOGY", "COVERAGE_FARM", "INSUFFICIENT_CONTEXT"],
  thresholds: { high: 0.8, low: 0.2 },
  itemId: (_input, idx) => `tt-${String(idx + 1).padStart(3, "0")}`,
  subject: (input) => input.file,
  extractFacts: (input) => input.facts,
  summarizeFacts: (facts) => facts.factSummary,
  shortCircuit: (facts) => {
    if (facts.coverageFarmName) {
      return {
        action: "delete_or_consolidate",
        reason: "Deterministic short-circuit: file name matches coverage-farm pattern.",
        requiresHuman: false,
      };
    }
    if (facts.literalOnlyAssertion || facts.selfDerivedExpectation) {
      return {
        action: "rewrite_oracle",
        reason: "Deterministic short-circuit: literal-only or self-derived assertion detected statically.",
        requiresHuman: false,
      };
    }
    if (!facts.hasSutImport && facts.observedBoundary === "unit") {
      return {
        action: "delete_or_wire_sut",
        reason: "Deterministic short-circuit: unit test imports no production symbol.",
        requiresHuman: false,
      };
    }
    if (facts.hasSutImport && facts.hasTableOrPbt && facts.mockCount === 0 && facts.nondeterminismCount === 0) {
      return {
        action: "keep_verified",
        reason: "Deterministic short-circuit: clean data-driven/PBT test importing SUT with zero mocks or nondeterminism.",
        requiresHuman: false,
      };
    }
    if (facts.context === "incomplete") {
      return {
        action: "escalate_human",
        reason: "Deterministic short-circuit: file exceeds single-window limit; abstain instead of truncating.",
        requiresHuman: true,
      };
    }
    return null;
  },
  buildRequest: (input, facts, requestId): System1Request => ({
    id: requestId,
    candidateId: facts.id,
    rubricId: "test-value",
    question: "Given verified static facts and code, classify this ambiguous test file's behavioral value.",
    choices: testTriageCircuit.choices,
    factContext: facts.factSummary,
    snippet: input.snippet,
  }),
  resolve: (facts, answer) =>
    resolveThreeBandDecision({
      answer,
      validChoices: testTriageCircuit.choices,
      thresholds: testTriageCircuit.thresholds,
      contradictsStaticFacts:
        (answer?.choice === "BEHAVIOR" && (facts.mockCount >= 3 || facts.multiStatusCount > 0)) ||
        (answer?.choice === "TAUTOLOGY" && facts.hasSutImport && facts.hasTableOrPbt),
      highAction: (choice) => {
        if (choice === "BEHAVIOR") return { action: "keep_verified", requiresHuman: false };
        if (choice === "CHANGE_DETECTOR") return { action: "push_down_or_deepen", requiresHuman: true };
        if (choice === "TAUTOLOGY" || choice === "COVERAGE_FARM") {
          return { action: "rewrite_or_delete", requiresHuman: true };
        }
        return { action: "escalate_human", requiresHuman: true };
      },
      lowAction: "keep_advisory",
      escalateAction: "escalate_human",
      reasonPrefix: "test-triage",
    }),
};

interface PrRiskFacts {
  file: string;
  churn: number;
  hasCheatHit: boolean;
  isHighRiskPath: boolean;
  isDocOrTestOnly: boolean;
}

export const prRiskRouterCircuit: CircuitDefinition<PrRiskInput, PrRiskFacts> = {
  id: "pr-risk-router",
  version: "1.0.0",
  title: "PR Change-Risk Router Circuit",
  description:
    "90% deterministic diff-cheat & blast-radius rules + 10% BYO System 1 routing for medium-ambiguity code diffs.",
  rubricId: "change-risk-tier",
  choices: ["low_auto_merge", "medium_single_review", "high_two_review_or_canary", "insufficient_context"],
  thresholds: { high: 0.85, low: 0.2 },
  itemId: (_input, idx) => `pr-${String(idx + 1).padStart(3, "0")}`,
  subject: (input) => input.file,
  extractFacts: (input) => ({
    file: input.file,
    churn: input.addedLines + input.removedLines,
    hasCheatHit: input.hasCheatHit,
    isHighRiskPath: HIGH_RISK_PATH.test(input.file),
    isDocOrTestOnly: DOC_OR_TEST_ONLY.test(input.file),
  }),
  summarizeFacts: (f) =>
    `file=${f.file}; churn=${f.churn}; cheat=${f.hasCheatHit}; highRiskPath=${f.isHighRiskPath}; docOrTest=${f.isDocOrTestOnly}`,
  shortCircuit: (f) => {
    if (f.hasCheatHit) {
      return {
        action: "block_merge",
        reason: "Deterministic short-circuit: diff-cheats violation detected.",
        requiresHuman: true,
      };
    }
    if (f.isHighRiskPath || f.churn >= 400) {
      return {
        action: "two_review_or_canary",
        reason: "Deterministic short-circuit: high-blast-radius path or large diff (>= 400 lines).",
        requiresHuman: true,
      };
    }
    if (f.isDocOrTestOnly && f.churn <= 60) {
      return {
        action: "auto_merge_candidate",
        reason: "Deterministic short-circuit: bounded doc/test-only change (<= 60 lines) with zero cheats.",
        requiresHuman: false,
      };
    }
    return null;
  },
  buildRequest: (input, facts, requestId): System1Request => ({
    id: requestId,
    candidateId: requestId,
    rubricId: "change-risk-tier",
    question: "Assign review risk tier for this code diff based on verified path and churn facts.",
    choices: prRiskRouterCircuit.choices,
    factContext: prRiskRouterCircuit.summarizeFacts(facts),
    snippet: input.diffSnippet.slice(0, 1800),
  }),
  resolve: (facts, answer) =>
    resolveThreeBandDecision({
      answer,
      validChoices: prRiskRouterCircuit.choices,
      thresholds: prRiskRouterCircuit.thresholds,
      contradictsStaticFacts: answer?.choice === "low_auto_merge" && (facts.isHighRiskPath || facts.churn > 200),
      highAction: (choice) => {
        if (choice === "low_auto_merge") return { action: "auto_merge_candidate", requiresHuman: false };
        if (choice === "medium_single_review") return { action: "single_review", requiresHuman: true };
        return { action: "two_review_or_canary", requiresHuman: true };
      },
      lowAction: "single_review",
      escalateAction: "single_review",
      reasonPrefix: "pr-risk-router",
    }),
};

interface InstructionFacts {
  file: string;
  line: number;
  alreadyEnforced: boolean;
  hasConflict: boolean;
  looksMechanical: boolean;
}

export const instructionLintPromoterCircuit: CircuitDefinition<InstructionRuleInput, InstructionFacts> = {
  id: "instruction-lint-promoter",
  version: "1.0.0",
  title: "Instruction-to-Linter Promotion Circuit",
  description:
    "90% deterministic filter for AGENTS.md/SKILL.md clauses already enforced or conflicting + 10% BYO System 1 judgment on mechanical lint candidates.",
  rubricId: "instruction-to-lint",
  choices: ["promotable_deterministic_rule", "already_enforced", "non_mechanical_guidance", "insufficient_context"],
  thresholds: { high: 0.8, low: 0.2 },
  itemId: (_input, idx) => `il-${String(idx + 1).padStart(3, "0")}`,
  subject: (input) => `${input.file}:${input.line}`,
  extractFacts: (input) => ({
    file: input.file,
    line: input.line,
    alreadyEnforced: input.alreadyEnforced,
    hasConflict: input.hasConflict,
    looksMechanical: PROMOTABLE_MECHANICAL.test(input.clause),
  }),
  summarizeFacts: (f) =>
    `file=${f.file}:${f.line}; alreadyEnforced=${f.alreadyEnforced}; conflict=${f.hasConflict}; mechanicalSignal=${f.looksMechanical}`,
  shortCircuit: (f) => {
    if (f.hasConflict) {
      return {
        action: "resolve_conflict",
        reason: "Deterministic short-circuit: clause conflicts with another instruction policy.",
        requiresHuman: true,
      };
    }
    if (f.alreadyEnforced) {
      return {
        action: "prune_redundant_prose",
        reason: "Deterministic short-circuit: rule is already enforced by vstack/linter.",
        requiresHuman: false,
      };
    }
    if (!f.looksMechanical) {
      return {
        action: "keep_as_guidance",
        reason: "Deterministic short-circuit: advisory guidance without mechanical prohibition verb.",
        requiresHuman: false,
      };
    }
    return null;
  },
  buildRequest: (input, facts, requestId): System1Request => ({
    id: requestId,
    candidateId: requestId,
    rubricId: "instruction-to-lint",
    question: "Can this mechanical agent instruction clause be promoted to an AST/compiler lint rule?",
    choices: instructionLintPromoterCircuit.choices,
    factContext: instructionLintPromoterCircuit.summarizeFacts(facts),
    snippet: input.clause.slice(0, 800),
  }),
  resolve: (_facts, answer) =>
    resolveThreeBandDecision({
      answer,
      validChoices: instructionLintPromoterCircuit.choices,
      thresholds: instructionLintPromoterCircuit.thresholds,
      contradictsStaticFacts: false,
      highAction: (choice) => {
        if (choice === "promotable_deterministic_rule") return { action: "promote_to_linter", requiresHuman: true };
        if (choice === "already_enforced") return { action: "prune_redundant_prose", requiresHuman: false };
        return { action: "keep_as_guidance", requiresHuman: false };
      },
      lowAction: "keep_as_guidance",
      escalateAction: "escalate_human",
      reasonPrefix: "instruction-lint-promoter",
    }),
};

interface PerfAdvisorFacts {
  file: string;
  lines: number;
  staticHitCount: number;
  staticHitRules: string[];
  timeExponent: number | null;
  spaceExponent: number | null;
  context: "complete" | "incomplete";
}

export const perfArchitectureAdvisorCircuit: CircuitDefinition<PerfAdvisorInput, PerfAdvisorFacts> = {
  id: "perf-architecture-advisor",
  version: "1.0.0",
  title: "Performance & Algorithmic Architecture Advisor Circuit",
  description:
    "90% deterministic complexity lints & Big-O scaling filter + 10% BYO System 1 optimization-family classification on verified hotspots.",
  rubricId: "perf-architecture",
  choices: [
    "algorithmic_complexity",
    "data_layout_locality",
    "batch_or_index_io",
    "bounded_memory_streaming",
    "no_change_needed",
    "insufficient_context",
  ],
  thresholds: { high: 0.8, low: 0.2 },
  itemId: (_input, idx) => `pa-${String(idx + 1).padStart(3, "0")}`,
  subject: (input) => input.file,
  extractFacts: (input) => ({
    file: input.file,
    lines: input.lines,
    staticHitCount: input.staticPerfHits.length,
    staticHitRules: input.staticPerfHits,
    timeExponent: typeof input.timeExponent === "number" ? input.timeExponent : null,
    spaceExponent: typeof input.spaceExponent === "number" ? input.spaceExponent : null,
    context: input.snippet.length <= 1800 ? "complete" : "incomplete",
  }),
  summarizeFacts: (f) =>
    `file=${f.file}; lines=${f.lines}; staticPerfHits=${f.staticHitCount}(${f.staticHitRules.join(",")}); timeExp=${f.timeExponent ?? "n/a"}; spaceExp=${f.spaceExponent ?? "n/a"}; context=${f.context}`,
  shortCircuit: (f) => {
    if (f.staticHitCount > 0) {
      return {
        action: "fix_static_perf_smell",
        reason: `Deterministic short-circuit: ${f.staticHitCount} static complexity/IO lint hit(s) (${f.staticHitRules.join(", ")}).`,
        requiresHuman: false,
      };
    }
    if (f.timeExponent !== null && f.timeExponent <= 1.25 && (f.spaceExponent === null || f.spaceExponent <= 1.15)) {
      return {
        action: "keep_verified",
        reason: `Deterministic short-circuit: verified empirical scaling (timeExp=${f.timeExponent}) within linear/n-log-n budget.`,
        requiresHuman: false,
      };
    }
    if (f.context === "incomplete") {
      return {
        action: "escalate_human",
        reason: "Deterministic short-circuit: hotspot snippet exceeds single-window limit; abstain instead of truncating.",
        requiresHuman: true,
      };
    }
    return null;
  },
  buildRequest: (input, facts, requestId): System1Request => ({
    id: requestId,
    candidateId: requestId,
    rubricId: "perf-architecture",
    question:
      "Given verified complexity facts and code, select the primary performance/algorithmic optimization family (or no_change_needed).",
    choices: perfArchitectureAdvisorCircuit.choices,
    factContext: perfArchitectureAdvisorCircuit.summarizeFacts(facts),
    snippet: input.snippet.slice(0, 1800),
  }),
  resolve: (facts, answer) =>
    resolveThreeBandDecision({
      answer,
      validChoices: perfArchitectureAdvisorCircuit.choices,
      thresholds: perfArchitectureAdvisorCircuit.thresholds,
      contradictsStaticFacts: answer?.choice === "no_change_needed" && facts.timeExponent !== null && facts.timeExponent >= 1.75,
      highAction: (choice) => {
        if (choice === "no_change_needed") return { action: "keep_verified", requiresHuman: false };
        if (choice === "insufficient_context") return { action: "escalate_human", requiresHuman: true };
        return { action: `propose_${choice}`, requiresHuman: true };
      },
      lowAction: "keep_advisory",
      escalateAction: "escalate_human",
      reasonPrefix: "perf-architecture-advisor",
    }),
};

export const DEFAULT_CIRCUITS: readonly CircuitMeta[] = [
  testTriageCircuit,
  prRiskRouterCircuit,
  instructionLintPromoterCircuit,
  perfArchitectureAdvisorCircuit,
].map((c) => ({
  id: c.id as CircuitMeta["id"],
  version: c.version,
  title: c.title,
  description: c.description,
  rubricId: c.rubricId,
  choices: c.choices,
  thresholds: c.thresholds,
}));
