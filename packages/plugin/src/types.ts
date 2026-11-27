export type KnownLanguage = "typescript" | "javascript" | "csharp" | "python" | "rust" | "go";
export type Language = KnownLanguage | (string & {});

export type RepoArchetype = "library" | "service" | "frontend" | "fullstack";

export type RungId = "R0" | "R1" | "R2" | "R3" | "R4" | "R5" | "R6" | "R7" | "R8";

export type TestBoundary = "unit" | "component" | "host" | "contract" | "integration" | "mbt" | "e2e" | "unknown";

export type Severity = "error" | "warn" | "info";

export type KnownFindingCategory =
  | "cheat"
  | "test-smell"
  | "no-comments"
  | "structure"
  | "ci-hygiene"
  | "oracle-lock";

export type FindingCategory = KnownFindingCategory | (string & {});

export type HookEventKind = "post-edit" | "pre-edit" | "stop";
export type KnownHookHarness = "claude" | "codex" | "cursor" | "copilot" | "grok";
export type HookHarness = KnownHookHarness | (string & {});
export type CheckFileTier = "immediate" | "all";

export interface HookProjectConfig {
  enabled: boolean;
  tier: CheckFileTier;
  auditLog?: string;
  harnesses: HookHarness[];
}

export interface HookExecutionResult {
  exitCode: number;
  stdout: string;
  stderr?: string;
  findings: Finding[];
}

export interface CheckFileOptions {
  repoRoot?: string;
  tier?: CheckFileTier;
  content?: string;
  strict?: boolean;
  maxLines?: number;
}

export interface CheckFileResult {
  file: string;
  tier: CheckFileTier;
  language: Language | null | undefined;
  elapsedMs: number;
  findings: Finding[];
}

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

export interface ScannedFile {
  rel: string;
  abs: string;
  language?: Language;
  isTest: boolean;
  isWorkflow: boolean;
  isStub?: boolean;
  content: string;
  rawContent?: string;
  lines: number;
}

export interface DiscoveredRepo {
  root: string;
  files: ScannedFile[];
  allRelPaths: string[];
  languages: Language[];
  archetype: RepoArchetype;
  observedArchetype: RepoArchetype;
  manifest?: RungManifest;
  manifestError?: string;
  scopeExclusions: ScopeExclusion[];
  signals: ToolSignals;
  ci: CiExecutionSignals;
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
  | "symlink"
  | "skipped-tracked-dir"
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
  invalidDiagnostics?: string[];
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

export type TigerStylePillar = "safety" | "performance" | "developer-experience";
export type TigerStyleGrade = "strong" | "partial" | "missing" | "not-applicable";

export interface TigerStylePrincipleStatus {
  id: string;
  pillar: TigerStylePillar;
  name: string;
  rung: RungId;
  grade: TigerStyleGrade;
  score: number;
  mode: "gate" | "advisory";
  observed: string;
  violationsCount: number;
  gaps: string[];
}

export interface TigerStyleReport {
  overallScore: number;
  applicableCount: number;
  strongCount: number;
  partialCount: number;
  missingCount: number;
  principles: TigerStylePrincipleStatus[];
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
  tigerStyle?: TigerStyleReport;
  workspaces?: WorkspaceLadderSummary[];
  scopeExclusions: ScopeExclusion[];
  pushDownOpportunities: PushDownOpportunity[];
  findings: Finding[];
  missingLinters: Array<{ tool: string; priority: "P1" | "P2" | "P3"; why: string }>;
  testInventory: TestFileRecord[];
}

export type * from "./types-circuits.ts";

export interface PluginOperation {
  readonly type: "add" | "remove";
  readonly target: string;
}

export interface PluginStatusEntry {
  readonly id: string;
  readonly source: string | { readonly type: string };
  readonly status: "active" | "failed";
  readonly state: { readonly status: "active" | "failed"; readonly error?: string };
  readonly guarded: boolean;
  readonly error?: string;
}

export interface DiffLineEvent {
  file: string;
  line: number;
  kind: "add" | "del";
  raw: string;
  code: string;
}
