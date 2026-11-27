import type {
  CiExecutionSignals,
  DiscoveredRepo,
  Finding,
  Language,
  PushDownOpportunity,
  RungId,
  RungManifest,
  RungReceipt,
  RungStatus,
  ScanReport,
  ScannedFile,
  TestFileRecord,
  TigerStyleReport,
  ToolSignals,
} from "./types.ts";

export interface PluginRegistration {
  readonly dispose: () => Promise<void> | void;
}

export interface DomainEditor<TItem> {
  readonly list: () => readonly TItem[];
  readonly get: (id: string) => TItem | undefined;
  readonly add: (item: TItem) => void;
  readonly update: (id: string, fn: (item: TItem) => void) => void;
  readonly remove: (id: string) => void;
}

export interface DomainTransformHandle<TItem = Record<string, unknown>> {
  readonly transform: (cb: (editor: DomainEditor<TItem>) => void) => PluginRegistration;
}

export interface LanguagePluginSpec {
  readonly id: string;
  readonly extensions: readonly string[];
  readonly sfcExtensions?: readonly string[];
  readonly isTestFile?: (rel: string) => boolean;
  readonly isStubFile?: (rel: string) => boolean;
  readonly extractEmbeddedScript?: (rel: string, raw: string) => { language: Language; content: string } | undefined;
  readonly scanStructure?: (file: ScannedFile) => Finding[];
  readonly scanStateMachines?: (file: ScannedFile) => Finding[];
  readonly scanImmediateProd?: (file: ScannedFile, maskedCode: string) => Finding[];
  readonly [key: string]: unknown;
}

export interface SignalExtractInput {
  readonly files: readonly ScannedFile[];
  readonly allRelPaths: readonly string[];
  readonly languages: readonly Language[];
  readonly defaultBranch?: string;
}

export interface SignalPluginSpec {
  readonly id: string;
  readonly extract: (input: SignalExtractInput) => {
    readonly signals?: Partial<ToolSignals>;
    readonly ci?: Partial<CiExecutionSignals>;
  };
  readonly [key: string]: unknown;
}

export interface AnalyzerRunContext {
  readonly repo: DiscoveredRepo;
  readonly strict: boolean;
  readonly disableRules?: readonly string[];
  readonly receiptHmacKey?: string;
  readonly activeLanguages: readonly LanguagePluginSpec[];
  readonly testInventory?: readonly TestFileRecord[];
  readonly findingsSoFar?: readonly Finding[];
  readonly rungs?: readonly RungStatus[];
}

export interface AnalyzerRunOutput {
  readonly findings?: Finding[];
  readonly testInventory?: TestFileRecord[];
  readonly pushDownOpportunities?: PushDownOpportunity[];
  readonly receipts?: Partial<Record<RungId, RungReceipt>>;
  readonly tigerStyle?: TigerStyleReport;
}

export interface AnalyzerPluginSpec {
  readonly id: string;
  readonly phase?: "discovery" | "lint" | "test" | "post-rung";
  readonly tier?: "immediate" | "all" | "repo";
  readonly languages?: readonly string[];
  readonly run: (ctx: AnalyzerRunContext) => Finding[] | AnalyzerRunOutput | Promise<Finding[] | AnalyzerRunOutput>;
  readonly [key: string]: unknown;
}

export interface RungPluginSpec {
  readonly id: string;
  readonly rung?: RungId;
  readonly validateCommand?: (rung: RungId | "canary", command: string, repoRoot?: string) => string | null;
  readonly auditManifest?: (repoRoot: string, baseRef: string, opts?: { failClosedOnMissingBase?: boolean; downgradeOnly?: boolean }) => Finding[];
  readonly auditRungCoverage?: (repo: DiscoveredRepo, rungs: readonly RungStatus[], opts?: { requireWellCovered?: boolean; respectRatchet?: boolean }) => Finding[];
  readonly loadReceipts?: (repo: DiscoveredRepo, manifest?: RungManifest, opts?: { strict?: boolean; hmacKeyOverride?: string }) => { receipts: Partial<Record<RungId, RungReceipt>>; findings: Finding[] };
  readonly [key: string]: unknown;
}

export interface HarnessPluginSpec {
  readonly id: string;
  readonly label: string;
  readonly [key: string]: unknown;
}

export interface CircuitPluginSpec {
  readonly id: string;
  readonly version?: string;
  readonly title?: string;
  readonly description?: string;
  readonly [key: string]: unknown;
}

export interface ProviderPluginSpec {
  readonly id: string;
  readonly label?: string;
  readonly [key: string]: unknown;
}

export interface ReporterPluginSpec {
  readonly id: string;
  readonly format?: (report: ScanReport) => string;
  readonly buildTigerStyle?: (repo: DiscoveredRepo, findings: readonly Finding[], rungs: readonly RungStatus[]) => TigerStyleReport;
  readonly countDirectDeps?: (repo: DiscoveredRepo) => { count: number; manifestFile?: string };
  readonly [key: string]: unknown;
}

export interface CommandRunContext {
  readonly cmd: string;
  readonly rest: readonly string[];
  readonly target: string;
  readonly asJson: boolean;
  readonly asMd: boolean;
  readonly host: unknown;
}

export interface CommandPluginSpec {
  readonly id: string;
  readonly name: string;
  readonly usage?: string;
  readonly run: (ctx: CommandRunContext) => number | Promise<number>;
  readonly [key: string]: unknown;
}

export interface FindingHookEvent {
  readonly repo: DiscoveredRepo;
  findings: Finding[];
  readonly [key: string]: unknown;
}

export type FindingHookName = "filter" | "enrich";
export type FindingHookHandler = (event: Record<string, unknown>) => void | Promise<void>;

export interface VeristackPluginContext {
  readonly options: Record<string, unknown>;
  readonly language: DomainTransformHandle<LanguagePluginSpec>;
  readonly signal: DomainTransformHandle<SignalPluginSpec>;
  readonly analyzer: DomainTransformHandle<AnalyzerPluginSpec>;
  readonly rung: DomainTransformHandle<RungPluginSpec>;
  readonly harness: DomainTransformHandle<HarnessPluginSpec>;
  readonly circuit: DomainTransformHandle<CircuitPluginSpec>;
  readonly provider: DomainTransformHandle<ProviderPluginSpec>;
  readonly reporter: DomainTransformHandle<ReporterPluginSpec>;
  readonly command: DomainTransformHandle<CommandPluginSpec>;
  readonly finding: {
    readonly hook: (name: FindingHookName, handler: FindingHookHandler) => PluginRegistration;
  };
}

export interface VeristackPluginDefinition {
  readonly id: string;
  readonly guarded?: boolean;
  readonly setup: (
    ctx: VeristackPluginContext,
  ) => void | (() => void | Promise<void>) | Promise<void | (() => void | Promise<void>)>;
}

const PLUGIN_BRAND = Symbol.for("veristack.plugin");

export interface VeristackPlugin extends VeristackPluginDefinition {
  readonly [PLUGIN_BRAND]: true;
}

export function definePlugin(def: VeristackPluginDefinition): VeristackPlugin {
  if (!def || typeof def.id !== "string" || def.id.trim().length === 0) {
    throw new Error("Plugin.define requires a non-empty string id.");
  }
  if (typeof def.setup !== "function") {
    throw new Error(`Plugin '${def.id}' requires a setup(ctx) function.`);
  }
  return Object.freeze({
    ...def,
    id: def.id.trim(),
    [PLUGIN_BRAND]: true as const,
  });
}

export function isVeristackPlugin(val: unknown): val is VeristackPlugin {
  if (typeof val !== "object" || val === null) return false;
  const rec = val as Record<PropertyKey, unknown>;
  if (rec[PLUGIN_BRAND] === true) return true;
  return typeof rec.id === "string" && rec.id.length > 0 && typeof rec.setup === "function";
}

export const Plugin = Object.freeze({
  define: definePlugin,
});
