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

const CORE_SERVICES_SYMBOL = Symbol.for("veristack.coreServices.v1");

function resolveActiveServices(): CoreRuntimeServices {
  const holder = globalThis as Record<PropertyKey, unknown>;
  const existing = holder[CORE_SERVICES_SYMBOL];
  if (existing && typeof existing === "object") return existing as CoreRuntimeServices;
  const created: CoreRuntimeServices = {};
  holder[CORE_SERVICES_SYMBOL] = created;
  return created;
}

export function registerCoreServices(partial: Partial<CoreRuntimeServices>): void {
  Object.assign(resolveActiveServices(), partial);
}

export function getCoreServices(): Readonly<CoreRuntimeServices> {
  return resolveActiveServices();
}
