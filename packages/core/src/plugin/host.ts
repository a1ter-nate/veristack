import {
  applyRepoConfig,
  loadRepoConfig,
  soundnessClassForFinding,
  type AnalyzerPluginSpec,
  type AnalyzerRunOutput,
  type CheckFileOptions,
  type CheckFileResult,
  type CircuitPluginSpec,
  type CommandPluginSpec,
  type DiscoveredRepo,
  type Finding,
  type HarnessPluginSpec,
  type LanguagePluginSpec,
  type PluginOperation,
  type PluginStatusEntry,
  type ProviderPluginSpec,
  type PushDownOpportunity,
  type ReporterPluginSpec,
  type RungId,
  type RungPluginSpec,
  type RungReceipt,
  type ScanReport,
  type ScopeExclusion,
  type SignalPluginSpec,
  type TestFileRecord,
  type TigerStyleReport,
  type VeristackPluginContext,
} from "@veristack/plugin";
import { discoverRepoWithPlugins } from "../discover.ts";
import { buildRungStatuses, buildWorkspaceLadders } from "../rungs/coverage.ts";
import { auditDeclaredArchetype } from "../rungs/manifest.ts";
import { createDomainStore, createFindingHookStore, type DomainRegistryStore, type FindingHookStore } from "./domain-state.ts";
import { builtinPluginManifest } from "./internal.ts";
import { PluginSupervisor, type QueuedPluginRecord } from "./supervisor.ts";

export interface PluginHostOptions {
  readonly repoDir?: string;
  readonly plugins?: readonly unknown[];
  readonly operations?: readonly PluginOperation[];
  readonly includeBuiltins?: boolean;
  readonly strict?: boolean;
}

export interface HostScanOptions {
  readonly strict?: boolean;
  readonly configPath?: string;
  readonly disableRules?: readonly string[];
  readonly receiptHmacKey?: string;
}

export interface CoreRegistries {
  readonly languages: () => readonly LanguagePluginSpec[];
  readonly signals: () => readonly SignalPluginSpec[];
  readonly analyzers: () => readonly AnalyzerPluginSpec[];
  readonly rungs: () => readonly RungPluginSpec[];
}

export interface ExtensionRegistries {
  readonly harnesses: () => readonly HarnessPluginSpec[];
  readonly circuits: () => readonly CircuitPluginSpec[];
  readonly providers: () => readonly ProviderPluginSpec[];
  readonly reporters: () => readonly ReporterPluginSpec[];
  readonly commands: () => readonly CommandPluginSpec[];
}

export type HostRegistries = CoreRegistries & ExtensionRegistries;

export interface VeristackHostInstance {
  readonly registries: HostRegistries;
  readonly list: () => readonly PluginStatusEntry[];
  readonly activate: (plugins: readonly unknown[], operations?: readonly PluginOperation[]) => Promise<void>;
  readonly dispose: () => Promise<void>;
  readonly discover: (repoDir: string) => DiscoveredRepo;
  readonly scan: (repoDir: string, opts?: HostScanOptions) => Promise<ScanReport>;
  readonly scanSync: (repoDir: string, opts?: HostScanOptions) => ScanReport;
  readonly checkFile: (filePath: string, opts?: CheckFileOptions) => Promise<CheckFileResult>;
}

const SAFE_ALLOW_EXCLUDED_PREFIX = /^(?:examples|fixtures|testdata|__fixtures__|snapshots)\//i;

function matchAllowPattern(pattern: string, target: string): boolean {
  const normPat = pattern.trim().replace(/^\/+/, "");
  const normTarget = target.replace(/^\/+/, "");
  if (!normPat) return false;
  if (normPat === normTarget) return true;
  const isDir = normPat.endsWith("/");
  const body = isDir ? normPat.slice(0, -1) : normPat;
  const escaped = body.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "__DBL__").replace(/\*/g, "[^/]*").replace(/__DBL__/g, ".*");
  return new RegExp(`^${escaped}${isDir ? "(?:/.*)?$" : "$"}`).test(normTarget);
}

function filterUnallowlistedExclusions(exclusions: readonly ScopeExclusion[], allowExcluded: readonly string[]): ScopeExclusion[] {
  if (allowExcluded.length === 0) return [...exclusions];
  return exclusions.filter((ex) => {
    if (ex.reason === "truncated") return true;
    const norm = ex.path.replace(/\\/g, "/").replace(/^\/+/, "");
    if (!SAFE_ALLOW_EXCLUDED_PREFIX.test(norm)) return true;
    return !allowExcluded.some((pat) => matchAllowPattern(pat, norm));
  });
}

function recommendMissingLinters(repo: DiscoveredRepo): ScanReport["missingLinters"] {
  const s = repo.signals;
  const isTs = repo.languages.includes("typescript") || repo.languages.includes("javascript");
  const isCs = repo.languages.includes("csharp");
  const missing: ScanReport["missingLinters"] = [];
  if (isTs && !s.hasOxlint) missing.push({ tool: "oxlint", priority: "P1", why: "50–100x faster Rust linter for JS/TS with JS plugin support." });
  if (isTs && !s.hasAntiSlop) missing.push({ tool: "dmmulroy/anti-slop", priority: "P1", why: "Blocks 15 TS escape-hatch & untyped contract slop patterns." });
  if (isTs && !s.hasLandmines) missing.push({ tool: "@interfere/landmines", priority: "P1", why: "Blocks test doubles, sleeps, retries, conditional expects & parameter branches." });
  if (!s.hasDeslopPlease) missing.push({ tool: "deslop-please", priority: "P2", why: "SCIP-graph Ousterhout linter (field-leak, shallow-module, tangle, cycle) that cuts agent tokens/task." });
  if (isTs && !s.hasGoInternal) missing.push({ tool: "oxlint-plugin-go-internal", priority: "P2", why: "Enforces Go-style internal/ encapsulation across TS feature modules." });
  if (isTs && !s.hasKnipOrDeadCode) missing.push({ tool: "knip", priority: "P2", why: "Deletes dead files, unused exports/types & phantom dependencies agents copy." });
  if (isCs && !s.hasDesloppify) missing.push({ tool: "desloppify", priority: "P2", why: "Full C# + TS structural quality harness with CI scoring." });
  if (!s.hasPreCommitHook) missing.push({ tool: "lefthook", priority: "P3", why: "Runs formatter, no-comments, and fast lints in < 2s before push." });
  return missing;
}

function absorbAnalyzerOutput(
  out: Finding[] | AnalyzerRunOutput,
  bucket: { findings: Finding[]; testInventory: TestFileRecord[]; pushDowns: PushDownOpportunity[] },
): void {
  if (Array.isArray(out)) {
    bucket.findings.push(...out);
    return;
  }
  if (out.findings) bucket.findings.push(...out.findings);
  if (out.testInventory) bucket.testInventory.push(...out.testInventory);
  if (out.pushDownOpportunities) bucket.pushDowns.push(...out.pushDownOpportunities);
}

function finalizeScanReport(input: {
  repo: DiscoveredRepo;
  rawFindings: Finding[];
  testInventory: TestFileRecord[];
  pushDowns: PushDownOpportunity[];
  receipts: Map<RungId, RungReceipt>;
  registries: HostRegistries;
  opts: HostScanOptions;
}): ScanReport {
  const { repo, rawFindings, testInventory, pushDowns, receipts, registries, opts } = input;
  if (!repo.root) throw new Error("Discovered repo root is required.");
  const config = loadRepoConfig(repo.root, opts.configPath);
  const applied = applyRepoConfig(rawFindings, config, opts.disableRules);
  const findings = applied.findings.map((f) => (f.soundness ? f : { ...f, soundness: soundnessClassForFinding(f) }));
  const requireReceipts = Boolean(opts.strict) || Boolean(repo.manifest);
  const rungs = buildRungStatuses(repo, testInventory, { receipts, requireReceipts });
  if (opts.strict) {
    for (const rp of registries.rungs()) {
      if (typeof rp.auditRungCoverage === "function") {
        findings.push(...rp.auditRungCoverage(repo, rungs, { requireWellCovered: true, respectRatchet: false }).map((f) => (f.soundness ? f : { ...f, soundness: soundnessClassForFinding(f) })));
      }
    }
  }
  let tigerStyle: TigerStyleReport | undefined;
  for (const rep of registries.reporters()) if (typeof rep.buildTigerStyle === "function") tigerStyle = rep.buildTigerStyle(repo, findings, rungs);
  const workspaces = buildWorkspaceLadders(repo, testInventory, findings);
  const scopeExclusions = filterUnallowlistedExclusions(repo.scopeExclusions, repo.manifest?.allowExcluded ?? []);
  const hasWeakeningConfig = applied.disabledRules.length > 0 || config.ignore.length > 0 || Object.values(config.rules).some((level) => level !== "error");
  const hasActiveConfig = hasWeakeningConfig || Object.keys(config.rules).length > 0;
  const sourceFiles = repo.files.filter((f) => f.language && !f.isTest);
  const testFiles = repo.files.filter((f) => f.language && f.isTest);
  const prodLines = sourceFiles.reduce((s, f) => s + f.lines, 0);
  const testLines = testFiles.reduce((s, f) => s + f.lines, 0);
  const e2eFiles = testInventory.filter((t) => t.rung === "R7");
  const applicableRungs = rungs.filter((r) => r.coverageGrade !== "not-applicable");
  let overallCoverageScore = applicableRungs.length > 0 ? Math.round(applicableRungs.reduce((s, r) => s + r.coverageScore, 0) / applicableRungs.length) : 100;
  if (workspaces.length > 0) {
    const minWs = Math.min(...workspaces.map((w) => w.score));
    overallCoverageScore = minWs === 0 ? 0 : Math.min(overallCoverageScore, Math.round((overallCoverageScore + Math.round(workspaces.reduce((s, w) => s + w.score, 0) / workspaces.length)) / 2));
  }
  return {
    schemaVersion: 1, repo: repo.root, archetype: repo.archetype,
    ...(repo.manifest ? { declaredArchetype: repo.manifest.archetype } : {}),
    languages: repo.languages,
    ...(hasActiveConfig ? { config: { path: config.configPath, disabledRules: applied.disabledRules, suppressedCount: applied.suppressedCount, ...(hasWeakeningConfig ? {} : { monotonicStrengthenOnly: true }) } } : {}),
    summary: {
      sourceFiles: sourceFiles.length, testFiles: testFiles.length, prodLines, testLines,
      testToProdRatio: prodLines > 0 ? Number((testLines / prodLines).toFixed(2)) : 0,
      e2eFiles: e2eFiles.length, e2eTestCases: e2eFiles.reduce((s, t) => s + Math.max(1, t.testCaseCount), 0),
      totalFindings: findings.length, errorCount: findings.filter((f) => f.severity === "error").length,
      warnCount: findings.filter((f) => f.severity === "warn").length, cheatCount: findings.filter((f) => f.category === "cheat").length,
      noCommentCount: findings.filter((f) => f.category === "no-comments").length, pushDownCount: pushDowns.length,
      holeCount: applicableRungs.filter((r) => r.coverageGrade === "not-covered" || r.coverageGrade === "over-budget").length,
      poorlyCoveredCount: applicableRungs.filter((r) => r.coverageGrade === "poorly-covered").length,
      wellCoveredCount: applicableRungs.filter((r) => r.coverageGrade === "well-covered").length,
      applicableRungCount: applicableRungs.length, unexecutedRungCount: applicableRungs.filter((r) => !r.executedInCi).length,
      receiptVerifiedCount: applicableRungs.filter((r) => r.receiptVerified).length, excludedCount: scopeExclusions.length, overallCoverageScore,
    },
    rungs, ...(tigerStyle ? { tigerStyle } : {}), ...(workspaces.length > 0 ? { workspaces } : {}),
    scopeExclusions, pushDownOpportunities: pushDowns, findings, missingLinters: recommendMissingLinters(repo), testInventory,
  };
}

interface HostDomainStores {
  language: DomainRegistryStore<LanguagePluginSpec>;
  signal: DomainRegistryStore<SignalPluginSpec>;
  analyzer: DomainRegistryStore<AnalyzerPluginSpec>;
  rung: DomainRegistryStore<RungPluginSpec>;
  harness: DomainRegistryStore<HarnessPluginSpec>;
  circuit: DomainRegistryStore<CircuitPluginSpec>;
  provider: DomainRegistryStore<ProviderPluginSpec>;
  reporter: DomainRegistryStore<ReporterPluginSpec>;
  command: DomainRegistryStore<CommandPluginSpec>;
  finding: FindingHookStore;
}

function createHostStores(): HostDomainStores {
  return {
    language: createDomainStore<LanguagePluginSpec>("veristack.language"),
    signal: createDomainStore<SignalPluginSpec>("veristack.signal"),
    analyzer: createDomainStore<AnalyzerPluginSpec>("veristack.analyzer"),
    rung: createDomainStore<RungPluginSpec>("veristack.rung"),
    harness: createDomainStore<HarnessPluginSpec>("veristack.harness"),
    circuit: createDomainStore<CircuitPluginSpec>("veristack.circuit"),
    provider: createDomainStore<ProviderPluginSpec>("veristack.provider"),
    reporter: createDomainStore<ReporterPluginSpec>("veristack.reporter"),
    command: createDomainStore<CommandPluginSpec>("veristack.command"),
    finding: createFindingHookStore(),
  };
}

function collectBaseFindings(
  repo: DiscoveredRepo,
  registries: HostRegistries,
  scanOpts: HostScanOptions,
): { findings: Finding[]; receipts: Map<RungId, RungReceipt> } {
  const findings: Finding[] = [];
  if (repo.manifestError) {
    findings.push({ id: "RUNG:manifest-invalid:.verification/rungs.json", rule: "rung-manifest-invalid", category: "oracle-lock", rung: "R0", severity: "error", file: ".verification/rungs.json", line: 1, message: repo.manifestError, fix: "Fix .verification/rungs.json schema so declared archetype and rung commands are valid." });
  }
  findings.push(...auditDeclaredArchetype(repo.manifest, repo.observedArchetype, repo));
  const receipts = new Map<RungId, RungReceipt>();
  for (const rp of registries.rungs()) {
    if (typeof rp.loadReceipts === "function") {
      const loaded = rp.loadReceipts(repo, repo.manifest, { strict: scanOpts.strict, hmacKeyOverride: scanOpts.receiptHmacKey });
      for (const [k, v] of Object.entries(loaded.receipts)) if (v) receipts.set(k as RungId, v);
      findings.push(...loaded.findings);
    }
  }
  if (scanOpts.strict && repo.manifest?.rungs.R2 && !repo.manifest.rungs.R2.canary?.enabled) {
    findings.push({ id: "RUNG:r2-canary-required:.verification/rungs.json", rule: "rung-canary-required", category: "oracle-lock", rung: "R2", severity: "error", file: ".verification/rungs.json", line: 1, message: "Strict scan requires planted-fault canary (canary.enabled: true) on R2 so tests prove real fault detection.", fix: "Enable rungs.R2.canary in .verification/rungs.json." });
  }
  return { findings, receipts };
}

function executeScanSync(
  repo: DiscoveredRepo,
  stores: HostDomainStores,
  registries: HostRegistries,
  scanOpts: HostScanOptions,
): ScanReport {
  const { findings: baseFindings, receipts } = collectBaseFindings(repo, registries, scanOpts);
  const bucket = { findings: baseFindings, testInventory: [] as TestFileRecord[], pushDowns: [] as PushDownOpportunity[] };
  const runCtx = { repo, strict: Boolean(scanOpts.strict), disableRules: scanOpts.disableRules, receiptHmacKey: scanOpts.receiptHmacKey, activeLanguages: registries.languages() };
  for (const analyzer of registries.analyzers()) {
    if (typeof analyzer.run !== "function") continue;
    const out = analyzer.run(runCtx);
    if (!(out instanceof Promise)) absorbAnalyzerOutput(out, bucket);
  }
  const hooks = stores.finding.get();
  const hookEv = { repo, findings: bucket.findings };
  for (const fn of hooks.enrich) fn(hookEv);
  for (const fn of hooks.filter) fn(hookEv);
  return finalizeScanReport({ repo, rawFindings: hookEv.findings, testInventory: bucket.testInventory, pushDowns: bucket.pushDowns, receipts, registries, opts: scanOpts });
}

async function executeScanAsync(
  repo: DiscoveredRepo,
  stores: HostDomainStores,
  registries: HostRegistries,
  scanOpts: HostScanOptions,
): Promise<ScanReport> {
  const { findings: baseFindings, receipts } = collectBaseFindings(repo, registries, scanOpts);
  const bucket = { findings: baseFindings, testInventory: [] as TestFileRecord[], pushDowns: [] as PushDownOpportunity[] };
  const runCtx = { repo, strict: Boolean(scanOpts.strict), disableRules: scanOpts.disableRules, receiptHmacKey: scanOpts.receiptHmacKey, activeLanguages: registries.languages() };
  for (const analyzer of registries.analyzers()) {
    if (typeof analyzer.run !== "function") continue;
    const out = await analyzer.run(runCtx);
    absorbAnalyzerOutput(out, bucket);
  }
  const hooks = stores.finding.get();
  const hookEv = { repo, findings: bucket.findings };
  for (const fn of hooks.enrich) await fn(hookEv);
  for (const fn of hooks.filter) await fn(hookEv);
  return finalizeScanReport({ repo, rawFindings: hookEv.findings, testInventory: bucket.testInventory, pushDowns: bucket.pushDowns, receipts, registries, opts: scanOpts });
}

function buildHostInternals(opts: PluginHostOptions): {
  stores: HostDomainStores;
  registries: HostRegistries;
  supervisor: PluginSupervisor;
  host: VeristackHostInstance;
} {
  if (!opts) throw new Error("PluginHostOptions is required.");
  const stores = createHostStores();
  const ctxFactory = (): VeristackPluginContext => ({
    options: { repoDir: opts.repoDir, strict: Boolean(opts.strict) },
    language: stores.language.handle, signal: stores.signal.handle, analyzer: stores.analyzer.handle,
    rung: stores.rung.handle, harness: stores.harness.handle, circuit: stores.circuit.handle,
    provider: stores.provider.handle, reporter: stores.reporter.handle, command: stores.command.handle,
    finding: { hook: stores.finding.hook },
  });
  const registries: HostRegistries = {
    languages: () => stores.language.list(), signals: () => stores.signal.list(),
    analyzers: () => stores.analyzer.list(), rungs: () => stores.rung.list(),
    harnesses: () => stores.harness.list(), circuits: () => stores.circuit.list(),
    providers: () => stores.provider.list(), reporters: () => stores.reporter.list(),
    commands: () => stores.command.list(),
  };
  const supervisor = new PluginSupervisor({ ctxFactory, guardedIds: builtinPluginManifest.guarded, repoDir: opts.repoDir });
  const discover = (repoDir: string): DiscoveredRepo => {
    const validator = registries.rungs().find((r) => typeof r.validateCommand === "function")?.validateCommand;
    return discoverRepoWithPlugins(repoDir, { languages: registries.languages(), signals: registries.signals(), validateCommand: validator });
  };
  const host: VeristackHostInstance = {
    registries,
    list: () => supervisor.list(),
    activate: async (plugins, operations = []) => { await supervisor.activateAsync(supervisor.normalizeExternalPlugins(plugins), operations); },
    dispose: () => supervisor.disposeAll(),
    discover,
    scan: (repoDir, scanOpts = {}) => executeScanAsync(discover(repoDir), stores, registries, scanOpts),
    scanSync: (repoDir, scanOpts = {}) => executeScanSync(discover(repoDir), stores, registries, scanOpts),
    checkFile: async (filePath, cfOpts) => {
      const { getCoreServices } = await import("@veristack/plugin");
      const fn = getCoreServices().scanSingleFile;
      return fn ? fn(filePath, cfOpts) : { file: filePath, tier: cfOpts?.tier ?? "immediate", language: null, elapsedMs: 0, findings: [] };
    },
  };
  return { stores, registries, supervisor, host };
}

function buildBootQueue(opts: PluginHostOptions, supervisor: PluginSupervisor): QueuedPluginRecord[] {
  const includeBuiltins = opts.includeBuiltins ?? true;
  const preItems: QueuedPluginRecord[] = includeBuiltins
    ? builtinPluginManifest.pre.map((p) => ({ plugin: p, source: "builtin:pre", guarded: builtinPluginManifest.guarded.has(p.id) || p.guarded === true }))
    : [];
  const userItems = supervisor.normalizeExternalPlugins(opts.plugins ?? [], "user");
  const postItems: QueuedPluginRecord[] = includeBuiltins
    ? builtinPluginManifest.post.map((p) => ({ plugin: p, source: "builtin:post", guarded: builtinPluginManifest.guarded.has(p.id) || p.guarded === true }))
    : [];
  return [...preItems, ...userItems, ...postItems];
}

export function createPluginHostSync(opts: PluginHostOptions = {}): VeristackHostInstance {
  const { supervisor, host } = buildHostInternals(opts);
  const queue = buildBootQueue(opts, supervisor);
  supervisor.activateSync(queue, opts.operations ?? []);
  return host;
}

export async function createPluginHost(opts: PluginHostOptions = {}): Promise<VeristackHostInstance> {
  const { supervisor, host } = buildHostInternals(opts);
  const queue = buildBootQueue(opts, supervisor);
  await supervisor.activateAsync(queue, opts.operations ?? []);
  return host;
}

export const PluginHost = Object.freeze({
  create: createPluginHost,
  createSync: createPluginHostSync,
});
