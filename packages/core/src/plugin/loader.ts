import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { isVeristackPlugin, type VeristackPlugin } from "@veristack/plugin";

function importFreshFile(entryFile: string): Promise<unknown> {
  const mtimeMs = fs.existsSync(entryFile) ? Math.trunc(fs.statSync(entryFile).mtimeMs) : 0;
  const href = `${pathToFileURL(entryFile).href}?mtime=${mtimeMs}`;
  return import(href);
}

function resolveExportEntry(exportsField: unknown): string | undefined {
  if (typeof exportsField === "string") return exportsField;
  if (!exportsField || typeof exportsField !== "object" || Array.isArray(exportsField)) return undefined;
  const rec = exportsField as Record<string, unknown>;
  const dot = rec["."] ?? rec;
  if (typeof dot === "string") return dot;
  if (!dot || typeof dot !== "object" || Array.isArray(dot)) return undefined;
  const dotRec = dot as Record<string, unknown>;
  for (const key of ["bun", "import", "default", "module"]) {
    if (typeof dotRec[key] === "string") return dotRec[key] as string;
  }
  return undefined;
}

function resolveLocalPackageEntry(targetDir: string): string {
  const pkgPath = path.join(targetDir, "package.json");
  if (fs.existsSync(pkgPath) && fs.statSync(pkgPath).isFile()) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as {
      exports?: unknown;
      main?: unknown;
      module?: unknown;
    };
    const fromExports = resolveExportEntry(pkg.exports);
    if (fromExports) return path.resolve(targetDir, fromExports);
    if (typeof pkg.module === "string") return path.resolve(targetDir, pkg.module);
    if (typeof pkg.main === "string") return path.resolve(targetDir, pkg.main);
  }
  for (const fallback of ["src/index.ts", "index.ts", "index.mjs", "index.js"]) {
    const candidate = path.join(targetDir, fallback);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  throw new Error(`Could not resolve entry point for plugin directory '${targetDir}'.`);
}

function extractPluginsFromModule(mod: unknown, specifier: string): VeristackPlugin[] {
  if (!mod || typeof mod !== "object") {
    throw new Error(`Plugin module '${specifier}' did not export a plugin object.`);
  }
  const rec = mod as Record<string, unknown>;
  if (isVeristackPlugin(rec.default)) return [rec.default];
  if (Array.isArray(rec.default)) {
    const list = rec.default.filter(isVeristackPlugin);
    if (list.length > 0) return list;
  }
  const named: VeristackPlugin[] = [];
  for (const val of Object.values(rec)) {
    if (isVeristackPlugin(val)) named.push(val);
  }
  if (named.length === 0) {
    throw new Error(`Plugin module '${specifier}' does not export a Plugin.define(...) definition.`);
  }
  return named;
}

export async function loadExternalPluginTarget(
  target: string,
  repoDir?: string,
): Promise<{ plugins: VeristackPlugin[]; source: string }> {
  if (!target || target.trim().length === 0) {
    throw new Error("Plugin target must be a non-empty path or package specifier.");
  }
  const trimmed = target.trim();
  const baseDir = repoDir ? path.resolve(repoDir) : process.cwd();
  const maybeLocal = path.isAbsolute(trimmed) ? trimmed : path.resolve(baseDir, trimmed);

  if (fs.existsSync(maybeLocal)) {
    const stat = fs.statSync(maybeLocal);
    const entryFile = stat.isDirectory() ? resolveLocalPackageEntry(maybeLocal) : maybeLocal;
    const mod: unknown = await importFreshFile(entryFile);
    return { plugins: extractPluginsFromModule(mod, trimmed), source: entryFile };
  }

  const nmDir = path.join(baseDir, "node_modules", trimmed);
  if (fs.existsSync(nmDir) && fs.statSync(nmDir).isDirectory()) {
    const entryFile = resolveLocalPackageEntry(nmDir);
    const mod: unknown = await importFreshFile(entryFile);
    return { plugins: extractPluginsFromModule(mod, trimmed), source: entryFile };
  }

  const req = createRequire(path.join(baseDir, "package.json"));
  const resolved = req.resolve(trimmed);
  const mod: unknown = await importFreshFile(resolved);
  return { plugins: extractPluginsFromModule(mod, trimmed), source: resolved };
}
