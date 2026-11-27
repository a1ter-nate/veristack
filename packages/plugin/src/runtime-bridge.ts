import type {
  CheckFileOptions,
  CheckFileResult,
  DiscoveredRepo,
  Finding,
  RungId,
  RungManifest,
  RungReceipt,
  RungStatus,
  ScanReport,
  TestFileRecord,
} from "./types.ts";

export interface CoreRuntimeServices {
  discoverRepo?: (repoPath: string) => DiscoveredRepo;
  scanRepo?: (repoPath: string, opts?: Record<string, unknown>) => ScanReport;
  buildRungStatuses?: (
    repo: DiscoveredRepo,
    inventory: readonly TestFileRecord[],
    opts?: { receipts?: Map<RungId, RungReceipt>; requireReceipts?: boolean },
  ) => RungStatus[];
  loadRungManifest?: (repoRoot: string) => { path?: string; manifest?: RungManifest; error?: string };
  scanSingleFile?: (filePath: string, opts?: CheckFileOptions) => CheckFileResult;
  scanGitDiffCheats?: (repoPath: string, baseRef?: string) => Finding[];
  evaluateGreenfieldRungGate?: (repo: DiscoveredRepo) => Finding[];
  validateCommand?: (rung: RungId | "canary", command: string, repoRoot?: string) => string | null;
}

const activeServices: CoreRuntimeServices = {};

export function registerCoreServices(partial: Partial<CoreRuntimeServices>): void {
  Object.assign(activeServices, partial);
}

export function getCoreServices(): Readonly<CoreRuntimeServices> {
  return activeServices;
}
