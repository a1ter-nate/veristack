export {
  createEmptyCiSignals,
  createEmptySignals,
  isHostRepoFile,
  runGitClean,
  runGitCleanBuffer,
  stripLiteralsAndComments,
} from "./helpers.ts";
export {
  detectLanguage,
  globMatchesPath,
  isDeclarationStub,
  isTestFilePath,
  pathHelpers,
} from "./path-helpers.ts";
export {
  canStartJsRegex,
  maskCode,
  maskStrings,
  scanLexical,
  type LexicalCommentSpan,
  type LexicalScanResult,
  type MaskCodeMode,
} from "./lexical.ts";
export {
  definePlugin,
  isVeristackPlugin,
  Plugin,
  type AnalyzerPluginSpec,
  type AnalyzerRunContext,
  type AnalyzerRunOutput,
  type CircuitPluginSpec,
  type CommandPluginSpec,
  type CommandRunContext,
  type DomainEditor,
  type DomainTransformHandle,
  type FindingHookEvent,
  type FindingHookHandler,
  type FindingHookName,
  type HarnessPluginSpec,
  type LanguagePluginSpec,
  type PluginRegistration,
  type ProviderPluginSpec,
  type ReporterPluginSpec,
  type RungPluginSpec,
  type SignalExtractInput,
  type SignalPluginSpec,
  type VeristackPlugin,
  type VeristackPluginContext,
  type VeristackPluginDefinition,
} from "./plugin.ts";
export {
  applyRepoConfig,
  isRuleDisabled,
  loadRepoConfig,
  type AppliedConfigResult,
  type RuleLevel,
  type VstackConfig,
} from "./repo-config.ts";
export { getCoreServices, registerCoreServices, type CoreRuntimeServices } from "./runtime-bridge.ts";
export {
  hasNonFrameworkImport,
  lineOf,
  scanTestHarnessGuards,
  scanVitestConfigs,
} from "./test-lexical.ts";
export type * from "./types.ts";
