import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseSync } from "oxc-parser";

export const VERISTACK_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export interface ImportEdge {
  readonly fromRel: string;
  readonly specifier: string;
  readonly line: number;
}

export interface DirectoryAudit {
  readonly files: string[];
  readonly totalLines: number;
  readonly imports: ImportEdge[];
}

export interface PluginStatusEntry {
  readonly id: string;
  readonly source: string | { readonly type: string };
  readonly status?: "active" | "failed";
  readonly state?: { readonly status: "active" | "failed"; readonly error?: string };
  readonly guarded?: boolean;
  readonly error?: string;
}

export interface PluginRegistration {
  readonly dispose: () => Promise<void> | void;
}

export interface StateInstance<TState, TEditor> {
  readonly get: () => TState;
  readonly transform: (cb: (editor: TEditor) => void) => unknown;
  readonly reload: () => unknown;
  readonly revision: () => number;
}

export interface DomainEditor<TItem> {
  readonly list: () => readonly TItem[];
  readonly get: (id: string) => TItem | undefined;
  readonly add: (item: TItem) => void;
  readonly update?: (id: string, fn: (item: TItem) => void) => void;
  readonly remove: (id: string) => void;
}

export interface VeristackPluginContext {
  readonly options: Record<string, unknown>;
  readonly language: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly signal: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly analyzer: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly rung: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly harness: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly circuit: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly provider: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly reporter: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly command: {
    readonly transform: (cb: (editor: DomainEditor<Record<string, unknown>>) => void) => Promise<PluginRegistration> | PluginRegistration;
  };
  readonly finding: {
    readonly hook: (
      name: "filter" | "enrich",
      handler: (event: Record<string, unknown>) => void | Promise<void>,
    ) => Promise<PluginRegistration> | PluginRegistration;
  };
}

export interface VeristackPluginDefinition {
  readonly id: string;
  readonly guarded?: boolean;
  readonly setup: (
    ctx: VeristackPluginContext,
  ) => void | (() => void | Promise<void>) | Promise<void | (() => void | Promise<void>)>;
}

export interface PluginOperation {
  readonly type: "add" | "remove";
  readonly target: string;
}

export interface VeristackHostInstance {
  readonly list: () => Promise<readonly PluginStatusEntry[]> | readonly PluginStatusEntry[];
  readonly activate: (
    plugins: readonly unknown[],
    operations?: readonly PluginOperation[],
  ) => Promise<void>;
  readonly dispose: () => Promise<void>;
  readonly scan: (
    repoDir: string,
    opts?: { readonly strict?: boolean; readonly configPath?: string },
  ) => Promise<{
    readonly findings: readonly { readonly id: string; readonly rule: string; readonly file: string; readonly severity: string }[];
    readonly languages: readonly string[];
    readonly summary: Record<string, unknown>;
  }>;
  readonly checkFile?: (
    filePath: string,
    opts?: { readonly tier?: "immediate" | "all" },
  ) => Promise<{ readonly findings: readonly { readonly rule: string }[] }>;
}

export interface LoadedVeristackRuntime {
  readonly definePlugin: (def: VeristackPluginDefinition) => unknown;
  readonly createState: <TState, TEditor>(opts: {
    readonly name?: string;
    readonly initial: () => TState;
    readonly editor: (state: TState) => TEditor;
  }) => StateInstance<TState, TEditor>;
  readonly createPluginHost: (opts?: {
    readonly repoDir?: string;
    readonly plugins?: readonly unknown[];
    readonly operations?: readonly PluginOperation[];
    readonly includeBuiltins?: boolean;
    readonly strict?: boolean;
  }) => Promise<VeristackHostInstance>;
}

function isSourceTsFile(fileName: string): boolean {
  const hasTsExt =
    fileName.endsWith(".ts") || fileName.endsWith(".tsx") || fileName.endsWith(".mts");
  return hasTsExt && !fileName.endsWith(".d.ts") && !fileName.endsWith(".test.ts") && !fileName.endsWith(".test.tsx");
}

function collectTsFiles(rootDir: string, relDir: string): string[] {
  if (!rootDir || !relDir) return [];
  const start = path.join(rootDir, relDir);
  if (!fs.existsSync(start)) return [];
  const results: string[] = [];
  const stack: string[] = [start];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === "dist" || entry.name === "out" || entry.name === ".git") {
        continue;
      }
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(abs);
      } else if (entry.isFile() && isSourceTsFile(entry.name)) {
        results.push(path.relative(rootDir, abs).split(path.sep).join("/"));
      }
    }
  }
  return results.sort();
}

function extractImportsFromFile(rootDir: string, relFile: string): ImportEdge[] {
  const abs = path.join(rootDir, relFile);
  if (!fs.existsSync(abs)) return [];
  const text = fs.readFileSync(abs, "utf8");
  const parsed = parseSync(relFile, text, { lang: relFile.endsWith(".tsx") ? "tsx" : "ts" });
  const edges: ImportEdge[] = [];
  for (const imp of parsed.module.staticImports) {
    const line = text.slice(0, imp.start).split("\n").length;
    edges.push({ fromRel: relFile, specifier: imp.moduleRequest.value, line });
  }
  for (const exp of parsed.module.staticExports) {
    for (const entry of exp.entries) {
      if (!entry.moduleRequest) continue;
      const line = text.slice(0, entry.start).split("\n").length;
      edges.push({ fromRel: relFile, specifier: entry.moduleRequest.value, line });
    }
  }
  return edges;
}

export function auditDirectory(rootDir: string, relDir: string): DirectoryAudit {
  if (!rootDir) throw new Error("rootDir is required");
  const files = collectTsFiles(rootDir, relDir);
  let totalLines = 0;
  const imports: ImportEdge[] = [];
  for (const rel of files) {
    const text = fs.readFileSync(path.join(rootDir, rel), "utf8");
    totalLines += text.split("\n").length;
    imports.push(...extractImportsFromFile(rootDir, rel));
  }
  return { files, totalLines, imports };
}

export function resolveRelativeImport(fromRel: string, specifier: string): string | null {
  if (!specifier.startsWith(".")) return null;
  return path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), specifier));
}

export function readPluginStatus(entry: PluginStatusEntry): "active" | "failed" | undefined {
  if (entry.state?.status) return entry.state.status;
  return entry.status;
}

function asRecord(val: unknown): Record<string, unknown> | null {
  if (typeof val !== "object" || val === null) return null;
  return val as Record<string, unknown>;
}

export async function loadVeristackPluginRuntime(): Promise<LoadedVeristackRuntime | null> {
  const pluginSdkPath = path.join(VERISTACK_ROOT, "packages/plugin/src/index.ts");
  const coreEntryPath = path.join(VERISTACK_ROOT, "packages/core/src/index.ts");
  if (!fs.existsSync(pluginSdkPath) || !fs.existsSync(coreEntryPath)) return null;

  const pluginMod = asRecord(await import(pathToFileURL(pluginSdkPath).href));
  const coreMod = asRecord(await import(pathToFileURL(coreEntryPath).href));
  if (!pluginMod || !coreMod) return null;

  const pluginNs = asRecord(pluginMod.Plugin);
  const definePlugin =
    typeof pluginNs?.define === "function"
      ? (pluginNs.define as LoadedVeristackRuntime["definePlugin"])
      : typeof pluginMod.definePlugin === "function"
        ? (pluginMod.definePlugin as LoadedVeristackRuntime["definePlugin"])
        : null;

  const stateNs = asRecord(coreMod.State) ?? asRecord(pluginMod.State);
  const createState =
    typeof stateNs?.create === "function"
      ? (stateNs.create as LoadedVeristackRuntime["createState"])
      : typeof coreMod.createState === "function"
        ? (coreMod.createState as LoadedVeristackRuntime["createState"])
        : null;

  const hostNs = asRecord(coreMod.PluginHost);
  const createPluginHost =
    typeof coreMod.createPluginHost === "function"
      ? (coreMod.createPluginHost as LoadedVeristackRuntime["createPluginHost"])
      : typeof hostNs?.create === "function"
        ? (hostNs.create as LoadedVeristackRuntime["createPluginHost"])
        : null;

  if (!definePlugin || !createState || !createPluginHost) return null;
  return { definePlugin, createState, createPluginHost };
}
