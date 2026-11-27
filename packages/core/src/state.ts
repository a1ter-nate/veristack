import { AsyncLocalStorage } from "node:async_hooks";

export interface StateRegistration {
  readonly dispose: () => void;
}

export interface StateInstance<TState, TEditor> {
  readonly name: string;
  readonly get: () => TState;
  readonly transform: (cb: (editor: TEditor) => void) => StateRegistration;
  readonly reload: () => TState;
  readonly revision: () => number;
  readonly subscribe: (listener: (state: TState, rev: number) => void) => StateRegistration;
  readonly dispose: () => void;
}

export interface StateCreateOptions<TState, TEditor> {
  readonly name?: string;
  readonly initial: () => TState;
  readonly editor: (state: TState) => TEditor;
}

export interface StateGroupScope {
  readonly track: (reg: StateRegistration) => StateRegistration;
  readonly dispose: () => void;
}

interface TransformEntry<TEditor> {
  readonly id: number;
  readonly cb: (editor: TEditor) => void;
  active: boolean;
}

const activeGroupStore = new AsyncLocalStorage<StateGroupScope>();
let batchDepth = 0;
const pendingFlushers = new Set<() => void>();
let nextTransformSeq = 1;

function flushPendingNotifications(): void {
  if (batchDepth > 0 || pendingFlushers.size === 0) return;
  const tasks = [...pendingFlushers];
  pendingFlushers.clear();
  for (const fn of tasks) fn();
}

export function batchState<T>(fn: () => T): T {
  batchDepth += 1;
  try {
    return fn();
  } finally {
    batchDepth -= 1;
    flushPendingNotifications();
  }
}

export function createStateGroup(): StateGroupScope {
  const registrations: StateRegistration[] = [];
  let disposed = false;
  return {
    track(reg: StateRegistration): StateRegistration {
      if (disposed) {
        reg.dispose();
        return reg;
      }
      registrations.push(reg);
      return reg;
    },
    dispose(): void {
      if (disposed) return;
      disposed = true;
      batchState(() => {
        for (let i = registrations.length - 1; i >= 0; i--) {
          try {
            registrations[i]?.dispose();
          } catch {
            void 0;
          }
        }
        registrations.length = 0;
      });
    },
  };
}

export function runInStateGroup<T>(
  fn: (scope: StateGroupScope) => T,
): { value: T; group: StateGroupScope } {
  const group = createStateGroup();
  try {
    const value = activeGroupStore.run(group, () => fn(group));
    return { value, group };
  } catch (err: unknown) {
    group.dispose();
    throw err;
  }
}

export async function runInStateGroupAsync<T>(
  fn: (scope: StateGroupScope) => Promise<T> | T,
): Promise<{ value: T; group: StateGroupScope }> {
  const group = createStateGroup();
  try {
    const value = await activeGroupStore.run(group, async () => await fn(group));
    return { value, group };
  } catch (err: unknown) {
    group.dispose();
    throw err;
  }
}

function replayTransforms<TState, TEditor>(
  opts: StateCreateOptions<TState, TEditor>,
  transforms: readonly TransformEntry<TEditor>[],
): TState {
  const nextDraft = opts.initial();
  const editor = opts.editor(nextDraft);
  for (const entry of transforms) {
    if (entry.active) entry.cb(editor);
  }
  return nextDraft;
}

function trackAmbient(reg: StateRegistration): StateRegistration {
  const ambient = activeGroupStore.getStore();
  return ambient ? ambient.track(reg) : reg;
}

export function createState<TState, TEditor>(
  opts: StateCreateOptions<TState, TEditor>,
): StateInstance<TState, TEditor> {
  if (!opts || typeof opts.initial !== "function" || typeof opts.editor !== "function") {
    throw new Error("State.create requires initial() and editor(state) functions.");
  }
  const name = opts.name ?? "state.anonymous";
  const transforms: TransformEntry<TEditor>[] = [];
  const listeners = new Set<(state: TState, rev: number) => void>();
  let current: TState = opts.initial();
  let rev = 0;

  const notify = (): void => {
    const snap = current;
    const snapRev = rev;
    for (const listener of listeners) listener(snap, snapRev);
  };

  const rebuild = (): TState => {
    current = replayTransforms(opts, transforms);
    rev += 1;
    if (listeners.size > 0) {
      if (batchDepth > 0) pendingFlushers.add(notify);
      else notify();
    }
    return current;
  };

  return {
    name,
    get: (): TState => current,
    revision: (): number => rev,
    reload: (): TState => rebuild(),
    transform(cb: (editor: TEditor) => void): StateRegistration {
      const entry: TransformEntry<TEditor> = { id: nextTransformSeq++, cb, active: true };
      transforms.push(entry);
      try {
        rebuild();
      } catch (err: unknown) {
        entry.active = false;
        const idx = transforms.indexOf(entry);
        if (idx >= 0) transforms.splice(idx, 1);
        throw err;
      }
      return trackAmbient({
        dispose(): void {
          if (!entry.active) return;
          entry.active = false;
          const idx = transforms.indexOf(entry);
          if (idx >= 0) transforms.splice(idx, 1);
          rebuild();
        },
      });
    },
    subscribe(listener: (state: TState, rev: number) => void): StateRegistration {
      listeners.add(listener);
      return trackAmbient({ dispose: () => { listeners.delete(listener); } });
    },
    dispose(): void {
      transforms.length = 0;
      listeners.clear();
      current = opts.initial();
      rev += 1;
    },
  };
}

export const State = Object.freeze({
  create: createState,
  batch: batchState,
  group: runInStateGroup,
  groupAsync: runInStateGroupAsync,
  createGroup: createStateGroup,
});
