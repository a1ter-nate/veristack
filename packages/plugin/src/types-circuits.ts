import type { TestBoundary } from "./types.ts";

export type KnownSystem1ProviderId = "laya" | "jev" | "local" | "command" | "fixture";
export type System1ProviderId = KnownSystem1ProviderId | (string & {});

export type KnownCircuitId =
  | "test-triage"
  | "pr-risk-router"
  | "instruction-lint-promoter"
  | "perf-architecture-advisor";
export type CircuitId = KnownCircuitId | (string & {});

export type CircuitBand = "short_circuit" | "high" | "uncertain" | "low" | "abstained" | "contradicted";

export interface CircuitThresholds {
  high: number;
  low: number;
}

export interface CircuitMeta {
  id: CircuitId;
  version: string;
  title: string;
  description: string;
  rubricId: System1RubricId;
  choices: readonly string[];
  thresholds: CircuitThresholds;
}

export interface CircuitReceipt {
  itemId: string;
  subject: string;
  shortCircuited: boolean;
  band: CircuitBand;
  action: string;
  reason: string;
  requiresHuman: boolean;
  corroborated: boolean;
  staticSummary: string;
  modelChoice: string | null;
  modelConfidence: number | null;
}

export interface CircuitRunReport {
  schemaVersion: 1;
  circuitId: string;
  circuitVersion: string;
  circuitHash: string;
  provider: string;
  thresholds: CircuitThresholds;
  totalInputs: number;
  shortCircuitedCount: number;
  modelCalledCount: number;
  shortCircuitRate: number;
  bandCounts: Record<CircuitBand, number>;
  receipts: CircuitReceipt[];
}

export type System1RubricId =
  | "test-value"
  | "test-boundary"
  | "push-down-eligibility"
  | "assertion-independence"
  | "mock-boundary"
  | "instruction-to-lint"
  | "change-risk-tier"
  | "perf-architecture";

export interface System1CandidateFacts {
  id: string;
  component: string;
  file: string;
  kind: "test" | "instruction";
  context: "complete" | "incomplete";
  lines: number;
  testCaseCount: number;
  observedBoundary: TestBoundary;
  hasSutImport: boolean;
  coverageFarmName: boolean;
  literalOnlyAssertion: boolean;
  selfDerivedExpectation: boolean;
  multiStatusCount: number;
  mockCount: number;
  networkMock: boolean;
  nondeterminismCount: number;
  hasTableOrPbt: boolean;
  factSummary: string;
}

export interface System1Request {
  id: string;
  candidateId: string;
  rubricId: System1RubricId;
  question: string;
  choices: readonly string[];
  factContext: string;
  snippet: string;
}

export interface System1ModelAnswer {
  id: string;
  choice: string | null;
  confidence: number | null;
  abstained: boolean;
}

export interface System1Judgment {
  candidateId: string;
  file: string;
  component: string;
  rubricId: System1RubricId;
  staticLabel: string;
  modelChoice: string | null;
  modelScore: number | null;
  verdict: "corroborated_issue" | "corroborated_clear" | "static_advisory" | "disagreed_human_review" | "abstained";
  reason: string;
  humanReviewRequired: true;
}

export interface System1ClassificationReport {
  schemaVersion: 1;
  repo: string;
  rubricVersion: string;
  rubricHash: string;
  mode: "static-preclassify" | "corroborated-system1";
  provider?: System1ProviderId;
  calibrationStatus: "uncalibrated_advisory_only";
  scoreSemantics: "choice_concentration_not_calibrated_precision";
  releaseBar: {
    minPrecision: number;
    minRecall: number;
    minDecisionCoverage: number;
    minPositivesPerRubric: number;
    minNegativesPerRubric: number;
  };
  totalEligible: number;
  selectedCount: number;
  truncated: boolean;
  componentDistribution: Array<{ component: string; total: number; selected: number }>;
  candidates: System1CandidateFacts[];
  requests: System1Request[];
  judgments: System1Judgment[];
}
