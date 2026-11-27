export type { DiscoveredRepo, ScannedFile } from "@veristack/plugin";
export { runCli } from "./cli.ts";
export { detectLanguageFromSpecs, discoverRepoWithPlugins, isTestFilePath, type DiscoverRepoOptions } from "./discover.ts";
export { formatFindingsList, formatMarkdownReport, formatSystem1Report, formatTerminalReport } from "./format.ts";
export { discoverRepo, getDefaultHostSync, scanRepo, type ScanOptions } from "./ladder.ts";
export {
  createPluginHost,
  createPluginHostSync,
  PluginHost,
  type HostRegistries,
  type HostScanOptions,
  type PluginHostOptions,
  type VeristackHostInstance,
} from "./plugin/host.ts";
export {
  buildRatchetBaseline,
  evaluateRatchet,
  writeRatchetBaseline,
  type RatchetBaseline,
  type RatchetDelta,
  type RatchetEvaluation,
  type RatchetRungEntry,
  type RatchetRungRegression,
} from "./ratchet.ts";
export { buildRungStatuses, buildWorkspaceLadders, type RungCoverageOptions } from "./rungs/coverage.ts";
export {
  auditDeclaredArchetype,
  discoverWorkspaces,
  inferArchetypeFromFiles,
  isHostRepoFile,
  loadRungManifest,
  validateRungCommand,
} from "./rungs/manifest.ts";
export { recommendPackagesForRung } from "./rungs/packages.ts";
export {
  batchState,
  createState,
  createStateGroup,
  runInStateGroup,
  runInStateGroupAsync,
  State,
  type StateCreateOptions,
  type StateGroupScope,
  type StateInstance,
  type StateRegistration,
} from "./state.ts";
