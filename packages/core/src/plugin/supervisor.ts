import {
  isVeristackPlugin,
  type PluginOperation,
  type PluginStatusEntry,
  type VeristackPlugin,
  type VeristackPluginContext,
} from "@veristack/plugin";
import { State, type StateGroupScope } from "../state.ts";
import { loadExternalPluginTarget } from "./loader.ts";

export interface QueuedPluginRecord {
  readonly plugin: VeristackPlugin;
  readonly source: string;
  readonly guarded: boolean;
}

interface ActivePluginRecord {
  readonly entry: PluginStatusEntry;
  readonly group?: StateGroupScope;
  readonly teardown?: () => void | Promise<void>;
}

function matchesRemoveTarget(pluginId: string, target: string): boolean {
  const norm = target.trim();
  if (!norm) return false;
  if (norm === "*") return true;
  if (norm.endsWith("*")) return pluginId.startsWith(norm.slice(0, -1));
  return pluginId === norm;
}

export function isPluginRemoved(
  id: string,
  isGuarded: boolean,
  operations: readonly PluginOperation[],
): boolean {
  if (isGuarded) return false;
  for (const op of operations) {
    if (op.type === "remove" && matchesRemoveTarget(id, op.target)) return true;
  }
  return false;
}

export class PluginSupervisor {
  private readonly records = new Map<string, ActivePluginRecord>();
  private readonly ctxFactory: () => VeristackPluginContext;
  private readonly guardedIds: ReadonlySet<string>;
  private readonly repoDir?: string;

  constructor(opts: {
    readonly ctxFactory: () => VeristackPluginContext;
    readonly guardedIds: ReadonlySet<string>;
    readonly repoDir?: string;
  }) {
    this.ctxFactory = opts.ctxFactory;
    this.guardedIds = opts.guardedIds;
    this.repoDir = opts.repoDir;
  }

  list(): readonly PluginStatusEntry[] {
    return [...this.records.values()].map((r) => r.entry);
  }

  private recordFailure(id: string, source: string, guarded: boolean, err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    const entry: PluginStatusEntry = {
      id,
      source,
      status: "failed",
      state: { status: "failed", error: message },
      guarded,
      error: message,
    };
    this.records.set(id, { entry });
  }

  activateSync(items: readonly QueuedPluginRecord[], operations: readonly PluginOperation[] = []): void {
    for (const item of items) {
      const guarded = item.guarded || item.plugin.guarded === true || this.guardedIds.has(item.plugin.id);
      if (isPluginRemoved(item.plugin.id, guarded, operations)) continue;
      this.disposeByIdSync(item.plugin.id);
      try {
        const { value: teardown, group } = State.group(() => item.plugin.setup(this.ctxFactory()));
        const entry: PluginStatusEntry = {
          id: item.plugin.id,
          source: item.source,
          status: "active",
          state: { status: "active" },
          guarded,
        };
        this.records.set(item.plugin.id, {
          entry,
          group,
          teardown: typeof teardown === "function" ? teardown : undefined,
        });
      } catch (err: unknown) {
        this.recordFailure(item.plugin.id, item.source, guarded, err);
      }
    }
  }

  async activateAsync(
    items: readonly QueuedPluginRecord[],
    operations: readonly PluginOperation[] = [],
  ): Promise<void> {
    if (!Array.isArray(items)) throw new Error("items must be an array.");
    const queue: QueuedPluginRecord[] = [...items];
    for (const op of operations) {
      if (op.type !== "add") continue;
      try {
        const loaded = await loadExternalPluginTarget(op.target, this.repoDir);
        for (const p of loaded.plugins) {
          queue.push({ plugin: p, source: loaded.source, guarded: p.guarded === true });
        }
      } catch (err: unknown) {
        this.recordFailure(op.target, op.target, false, err);
      }
    }

    for (const item of queue) {
      const guarded = item.guarded || item.plugin.guarded === true || this.guardedIds.has(item.plugin.id);
      if (isPluginRemoved(item.plugin.id, guarded, operations)) continue;
      await this.disposeByIdAsync(item.plugin.id);
      try {
        const { value: teardown, group } = await State.groupAsync(async () => await item.plugin.setup(this.ctxFactory()));
        const entry: PluginStatusEntry = {
          id: item.plugin.id,
          source: item.source,
          status: "active",
          state: { status: "active" },
          guarded,
        };
        this.records.set(item.plugin.id, {
          entry,
          group,
          teardown: typeof teardown === "function" ? teardown : undefined,
        });
      } catch (err: unknown) {
        this.recordFailure(item.plugin.id, item.source, guarded, err);
      }
    }
  }

  normalizeExternalPlugins(raw: readonly unknown[], source = "inline"): QueuedPluginRecord[] {
    const out: QueuedPluginRecord[] = [];
    for (const candidate of raw) {
      if (isVeristackPlugin(candidate)) {
        out.push({ plugin: candidate, source, guarded: candidate.guarded === true });
      }
    }
    return out;
  }

  private disposeByIdSync(id: string): void {
    const existing = this.records.get(id);
    if (!existing) return;
    this.records.delete(id);
    try {
      existing.group?.dispose();
    } catch {
      void 0;
    }
  }

  private async disposeByIdAsync(id: string): Promise<void> {
    const existing = this.records.get(id);
    if (!existing) return;
    this.records.delete(id);
    if (existing.teardown) {
      try {
        await existing.teardown();
      } catch {
        void 0;
      }
    }
    try {
      existing.group?.dispose();
    } catch {
      void 0;
    }
  }

  async disposeAll(): Promise<void> {
    const ids = [...this.records.keys()].reverse();
    for (const id of ids) {
      await this.disposeByIdAsync(id);
    }
  }
}
