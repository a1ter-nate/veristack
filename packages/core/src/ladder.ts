import { registerCoreServices, type DiscoveredRepo, type ScanReport } from "@veristack/plugin";
import { createPluginHostSync, type HostScanOptions, type VeristackHostInstance } from "./plugin/host.ts";
import { buildRungStatuses } from "./rungs/coverage.ts";
import { loadRungManifest } from "./rungs/manifest.ts";

export type ScanOptions = HostScanOptions;

let defaultSyncHost: VeristackHostInstance | null = null;

export function getDefaultHostSync(): VeristackHostInstance {
  if (!defaultSyncHost) {
    const created = createPluginHostSync({ includeBuiltins: true });
    defaultSyncHost = created;
    registerCoreServices({
      discoverRepo: (p) => created.discover(p),
      scanRepo: (p, opts) => created.scanSync(p, opts as HostScanOptions | undefined),
      buildRungStatuses,
      loadRungManifest: (root) => loadRungManifest(root),
    });
  }
  return defaultSyncHost;
}

export function discoverRepo(repoPath: string): DiscoveredRepo {
  return getDefaultHostSync().discover(repoPath);
}

export function scanRepo(repoPath: string, options: ScanOptions = {}): ScanReport {
  return getDefaultHostSync().scanSync(repoPath, options);
}

registerCoreServices({
  discoverRepo: (p) => discoverRepo(p),
  scanRepo: (p, opts) => scanRepo(p, opts as HostScanOptions | undefined),
  buildRungStatuses,
  loadRungManifest: (root) => loadRungManifest(root),
});
