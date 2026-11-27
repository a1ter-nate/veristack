import type {
  DomainEditor,
  DomainTransformHandle,
  FindingHookHandler,
  FindingHookName,
  PluginRegistration,
} from "@veristack/plugin";
import { createState, type StateInstance } from "../state.ts";

export interface DomainRegistryStore<TItem extends Record<string, unknown>> {
  readonly state: StateInstance<Map<string, TItem>, DomainEditor<TItem>>;
  readonly handle: DomainTransformHandle<TItem>;
  readonly list: () => readonly TItem[];
  readonly get: (id: string) => TItem | undefined;
}

export function createDomainStore<TItem extends Record<string, unknown>>(
  name: string,
): DomainRegistryStore<TItem> {
  if (!name) throw new Error("Domain store name is required.");
  const state = createState<Map<string, TItem>, DomainEditor<TItem>>({
    name,
    initial: () => new Map<string, TItem>(),
    editor: (draft) => ({
      list: (): readonly TItem[] => [...draft.values()],
      get: (id: string): TItem | undefined => draft.get(id),
      add(item: TItem): void {
        const id = typeof item.id === "string" ? item.id.trim() : "";
        if (!id) throw new Error(`Domain '${name}' item must declare a non-empty string id.`);
        draft.set(id, item);
      },
      update(id: string, fn: (item: TItem) => void): void {
        const cur = draft.get(id);
        if (!cur) return;
        const cloned = { ...cur };
        fn(cloned);
        draft.set(id, cloned);
      },
      remove(id: string): void {
        draft.delete(id);
      },
    }),
  });

  return {
    state,
    handle: {
      transform: (cb): PluginRegistration => state.transform(cb),
    },
    list: (): readonly TItem[] => [...state.get().values()],
    get: (id: string): TItem | undefined => state.get().get(id),
  };
}

export interface FindingHookBuckets {
  readonly filter: FindingHookHandler[];
  readonly enrich: FindingHookHandler[];
}

export interface FindingHookStore {
  readonly state: StateInstance<FindingHookBuckets, { add: (name: FindingHookName, fn: FindingHookHandler) => void }>;
  readonly hook: (name: FindingHookName, handler: FindingHookHandler) => PluginRegistration;
  readonly get: () => FindingHookBuckets;
}

export function createFindingHookStore(): FindingHookStore {
  const state = createState<FindingHookBuckets, { add: (name: FindingHookName, fn: FindingHookHandler) => void }>({
    name: "veristack.finding.hooks",
    initial: () => ({ filter: [], enrich: [] }),
    editor: (draft) => ({
      add(name: FindingHookName, fn: FindingHookHandler): void {
        if (name === "filter") draft.filter.push(fn);
        else if (name === "enrich") draft.enrich.push(fn);
        else throw new Error(`Unsupported finding hook '${String(name)}'.`);
      },
    }),
  });

  return {
    state,
    hook: (name, handler): PluginRegistration => state.transform((ed) => ed.add(name, handler)),
    get: (): FindingHookBuckets => state.get(),
  };
}
