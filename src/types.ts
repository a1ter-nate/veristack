export type Language = "typescript" | "javascript" | "csharp" | "python" | "rust" | "go";

export type RepoArchetype = "library" | "service" | "frontend" | "fullstack";

export type RungId = "R0" | "R1" | "R2" | "R3" | "R4" | "R5" | "R6" | "R7" | "R8";

export type TestBoundary = "unit" | "component" | "host" | "contract" | "integration" | "mbt" | "e2e" | "unknown";

export type Severity = "error" | "warn" | "info";

export type FindingCategory =
  | "cheat"
  | "test-smell"
  | "no-comments"
  | "structure"
  | "ci-hygiene"
  | "oracle-lock";

export interface Finding {
  id: string;
  rule: string;
  category: FindingCategory;
  rung: RungId;
  severity: Severity;
  file: string;
  line: number;
  message: string;
  fix: string;
}

export interface PushDownOpportunity {
  file: string;
  line: number;
  currentRung: RungId;
  targetRung: RungId;
  pattern: string;
  reason: string;
  replacement: string;
  forbiddenWarning?: string;
}

export type RungCoverageGrade =
  | "well-covered"
  | "poorly-covered"
  | "not-covered"
  | "over-budget"
  | "not-applicable";

export interface RungCheck {
  id: string;
  label: string;
  weight: number;
  passed: boolean;
  executed: boolean;
  detail: string;
}

export interface CiExecutionSignals {
  hasCiWorkflows: boolean;
  workflowFiles: string[];
  runsFormatterOrLint: boolean;
  runsTypeOrStructureCheck: boolean;
  runsUnitTests: boolean;
  runsBoundaryOrMbtTests: boolean;
  runsIntegrationOrDbTests: boolean;
  runsMutationOrFormal: boolean;
  runsPerfOrBench: boolean;
  runsE2eTests: boolean;
  runsProdVerification: boolean;
}

export type ScopeExclusionReason =
  | "vstackignore"
  | "config-ignore"
  | "oversized"
  | "minified"
  | "truncated";

export interface ScopeExclusion {
  path: string;
  reason: ScopeExclusionReason;
  detail?: string;
}

export interface PlantedFaultSurvivor {
  file: string;
  line: number;
  operator: string;
  original: string;
  mutated: string;
}

export interface PlantedFaultReport {
  totalMutants: number;
  killedMutants: number;
  survivedMutants: number;
  invalidKills: number;
  killRate: number;
  minKillRate: number;
  passed: boolean;
  survivors: PlantedFaultSurvivor[];
}

export interface RungReceipt {
  schemaVersion: 1;
  rung: RungId;
  command: string;
  commitSha: string;
  treeHash: string;
  exitCode: number;
  durationMs: number;
  ciRunId?: string;
  metrics?: {
    testsPassed?: number;
    testsFailed?: number;
    mutationScore?: number;
    perfPassed?: boolean;
  };
  canary?: PlantedFaultReport;
  timestamp: string;
  digest: string;
}

export interface RungManifestEntry {
  command: string;
  required?: boolean;
  canary?: {
    enabled: boolean;
    testCommand?: string;
    targets?: string[];
    maxMutants?: number;
    minKillRate?: number;
  };
}

export interface RungManifest {
  schemaVersion: 1;
  archetype: RepoArchetype;
  allowExcluded?: string[];
  rungs: Partial<Record<RungId, RungManifestEntry>>;
  workspaces?: Array<{ name: string; path: string; archetype: RepoArchetype }>;
}

export interface WorkspaceLadderSummary {
  name: string;
  path: string;
  archetype: RepoArchetype;
  score: number;
  wellCoveredCount: number;
  applicableRungCount: number;
  highRiskFiles: number;
}

export interface RungStatus {
  rung: RungId;
  name: string;
  speedBudget: string;
  targetBudget: string;
  status: "covered" | "partial" | "hole" | "over-budget" | "not-applicable";
  coverageGrade: RungCoverageGrade;
  coverageScore: number;
  executedInCi: boolean;
  receiptVerified: boolean;
  adequacyKillRate?: number;
  idealCoverage: string;
  observedCoverage: string;
  checks: RungCheck[];
  observedCount: number;
  evidence: string[];
  gaps: string[];
}

export interface ToolSignals {
  hasFormatter: boolean;
  hasLinter: boolean;
  hasOxlint: boolean;
  hasAntiSlop: boolean;
  hasLandmines: boolean;
  hasGoInternal: boolean;
  hasDeslopPlease: boolean;
  hasDesloppify: boolean;
  hasStrictTypes: boolean;
  hasTsgo: boolean;
  hasKnipOrDeadCode: boolean;
  hasJscpd: boolean;
  hasArchFitness: boolean;
  hasPreCommitHook: boolean;
  hasCodeowners: boolean;
  hasReviewMd: boolean;
  hasAgentsMd: boolean;
  hasPbt: boolean;
  hasMbt: boolean;
  hasContractTool: boolean;
  hasComponentUiTool: boolean;
  hasMsw: boolean;
  hasMswStrict: boolean;
  hasTestcontainersOrRealDb: boolean;
  hasMigrationTest: boolean;
  hasBusDlqTest: boolean;
  hasDst: boolean;
  hasDryRun: boolean;
  hasMutationTool: boolean;
  hasFormalTool: boolean;
  hasFuzzTool: boolean;
  hasBombadil: boolean;
  hasVisualTool: boolean;
  hasPerfOrLoadTool: boolean;
  hasE2eTool: boolean;
  hasProdTelemetryOrCanary: boolean;
  hasDiffSelection: boolean;
}

export interface TestFileRecord {
  file: string;
  language: Language;
  lines: number;
  testCaseCount: number;
  boundary: TestBoundary;
  rung: RungId;
  hasTable: boolean;
  hasPbt: boolean;
  hasMbt: boolean;
  hasRealDb: boolean;
  hasRealBus: boolean;
  hasNetworkMock: boolean;
}

export interface ScanSummary {
  sourceFiles: number;
  testFiles: number;
  prodLines: number;
  testLines: number;
  testToProdRatio: number;
  e2eFiles: number;
  e2eTestCases: number;
  totalFindings: number;
  errorCount: number;
  warnCount: number;
  cheatCount: number;
  noCommentCount: number;
  pushDownCount: number;
  holeCount: number;
  poorlyCoveredCount: number;
  wellCoveredCount: number;
  applicableRungCount: number;
  unexecutedRungCount: number;
  receiptVerifiedCount: number;
  excludedCount: number;
  overallCoverageScore: number;
}

export interface ScanConfigMeta {
  path?: string;
  disabledRules: string[];
  suppressedCount: number;
}

export interface ScanReport {
  schemaVersion: 1;
  repo: string;
  archetype: RepoArchetype;
  declaredArchetype?: RepoArchetype;
  languages: Language[];
  config?: ScanConfigMeta;
  summary: ScanSummary;
  rungs: RungStatus[];
  workspaces?: WorkspaceLadderSummary[];
  scopeExclusions: ScopeExclusion[];
  pushDownOpportunities: PushDownOpportunity[];
  findings: Finding[];
  missingLinters: Array<{ tool: string; priority: "P1" | "P2" | "P3"; why: string }>;
  testInventory: TestFileRecord[];
}

export type System1ProviderId = "laya" | "jev" | "local" | "command" | "fixture";

export type CircuitId =
  | "test-triage"
  | "pr-risk-router"
  | "instruction-lint-promoter"
  | "perf-architecture-advisor";

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
