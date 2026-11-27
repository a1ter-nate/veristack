import fs from "node:fs";
import path from "node:path";
import {
  createEmptyCiSignals,
  createEmptySignals,
  isHostRepoFile,
  loadRepoConfig,
  pathHelpers,
  runGitClean,
  type CiExecutionSignals,
  type DiscoveredRepo,
  type Language,
  type LanguagePluginSpec,
  type RungId,
  type ScannedFile,
  type ScopeExclusion,
  type SignalPluginSpec,
  type ToolSignals,
} from "@veristack/plugin";
import { inferArchetypeFromFiles, loadRungManifest } from "./rungs/manifest.ts";

export interface DiscoverRepoOptions {
  readonly languages?: readonly LanguagePluginSpec[];
  readonly signals?: readonly SignalPluginSpec[];
  readonly validateCommand?: (rung: RungId | "canary", cmd: string, root?: string) => string | null;
}

const UNTRACKED_CACHE_SKIP_DIRS = new Set([
  ".git", "node_modules", ".next", ".nuxt", ".output", ".svelte-kit", ".vercel", ".netlify",
  ".expo", ".vite", ".parcel-cache", ".angular", ".turbo", ".cache", ".venv", "venv",
  "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".stryker-tmp",
  "StrykerOutput", "TestResults", "coverage", "dist", "build", "target", "obj", "vendor",
]);

const MAX_FILE_BYTES = 512_000;
const MAX_FILES = 12_000;
const PRIORITY_DIRS = new Set([".github", ".verification", ".circleci", ".husky", ".githooks", "ci", ".azure-pipelines", ".azuredevops"]);
const SOURCE_TREE_ROOT = /^(?:src|packages|services|apps|crates|libs|pkg|internal|cmd)\//i;
const ALWAYS_SKIP_DIRS = new Set([".git", "node_modules", ".repospec", ".runtime"]);
const WORKSPACE_BUILD_DIR = /^(?:apps|packages|services|crates|libs)\/[^/]+\/(?:dist|build|coverage|target|obj|bin|\.next|\.nuxt|\.output|\.svelte-kit|\.vite|\.turbo|\.cache|\.stryker-tmp|TestResults|StrykerOutput|__pycache__|\.venv|venv)$/i;
const HELPER_SCRIPT_ROOT = /^\.(?:github|agents|claude|cursor|codex|husky)\//i;
const ARCHIVED_DOCS_PATH = /^docs\/.*\/(?:data|archive|snapshots|artifacts)\//i;
const MINIFIED_FILE_PATH = /\.(?:min|bundle)\.[cm]?js$/i;

const READ_TEXT_BASENAMES = new Set([
  "package.json", "pyproject.toml", "cargo.toml", "go.mod", "codeowners", "agents.md", "claude.md",
  "gemini.md", ".cursorrules", "copilot-instructions.md", "skill.md", "review.md", "gates.md",
  "lefthook.yml", ".oxlintrc.json", ".oxlintrc.jsonc", "oxlint.config.ts", "turbo.json",
  "directory.build.props", "directory.packages.props", ".editorconfig", "stryker-config.json",
  "clippy.toml", ".clippy.toml", "rustfmt.toml", ".rustfmt.toml", "mutants.toml", "ruff.toml",
  ".ruff.toml", "mypy.ini", "pyrightconfig.json", "pytest.ini", "control-plan.json", "escapes.json",
  "knip.json", "knip.jsonc", ".golangci.yml", ".golangci.yaml", "biome.json", "biome.jsonc",
  "build.ps1", "build.cake", "cake.cs",
]);

export function detectLanguageFromSpecs(
  rel: string,
  specs: readonly LanguagePluginSpec[],
): Language | undefined {
  const lower = rel.toLowerCase();
  for (const spec of specs) {
    if (!Array.isArray(spec.extensions)) continue;
    for (const ext of spec.extensions) {
      if (typeof ext === "string" && ext.length > 0 && lower.endsWith(ext.toLowerCase())) {
        return spec.id;
      }
    }
  }
  return undefined;
}

export function isTestFilePath(rel: string, specs?: readonly LanguagePluginSpec[]): boolean {
  const hasLang = specs ? detectLanguageFromSpecs(rel, specs) !== undefined : undefined;
  return pathHelpers.isTestFilePath(rel, hasLang);
}

function isWorkflowPath(rel: string): boolean {
  const lower = rel.replace(/\\/g, "/").toLowerCase();
  const isYaml = lower.endsWith(".yml") || lower.endsWith(".yaml");
  return (
    (lower.startsWith(".github/workflows/") && isYaml) ||
    lower === "azure-pipelines.yml" ||
    lower === "azure-pipelines.yaml" ||
    lower === ".azure-pipelines.yml" ||
    lower === ".azure-pipelines.yaml" ||
    ((lower.startsWith("ci/") || lower.startsWith(".azure-pipelines/") || lower.startsWith(".azuredevops/")) && isYaml) ||
    lower === ".gitlab-ci.yml" ||
    lower === ".circleci/config.yml" ||
    lower === "bitbucket-pipelines.yml"
  );
}

function shouldReadText(rel: string, specs: readonly LanguagePluginSpec[]): boolean {
  const lower = rel.replace(/\\/g, "/").toLowerCase();
  const base = path.posix.basename(lower);
  if (detectLanguageFromSpecs(rel, specs) !== undefined || isWorkflowPath(rel) || READ_TEXT_BASENAMES.has(base)) return true;
  if ((lower.endsWith(".yml") || lower.endsWith(".yaml")) && (/(?:^|\/)(?:maestro|e2e|mobile-e2e|flows)\//.test(lower) || /(?:^|\/)\.github\/(?:.+\/)?action\.ya?ml$/.test(lower))) return true;
  if (/\.(?:vue|svelte|astro|css|bend|sh|bash|csproj|tla|qnt|als|dfy|lean|feature)$/.test(lower) || /^scripts\/[a-z0-9_.-]+$/.test(lower)) return true;
  if (lower.endsWith(".sql") && (/(?:^|\/)(?:migrations?|supabase|policies|rls|schema|db|sql|flyway)\//.test(lower) || base.endsWith("schema.sql"))) return true;
  if (lower.endsWith(".laws.json") || /(?:^|\/)\.verification\/(?:laws\/|chokepoints\.json|rungs\.json|hooks\.json|control-plan\.json|escapes\.json|behavior-changes\.json)/.test(lower)) return true;
  if (/^\.env\.(?:example|sample|template|dist)$/i.test(base) || base === "dockerfile" || base.startsWith("dockerfile.")) return true;
  return /^tsconfig(?:\.[^/]+)?\.json$/.test(base) || /^(?:vitest|vite|playwright|cypress|k6)\.config\.[cm]?[jt]s$/.test(base) || /^\.?lighthouserc\.(?:json|ya?ml|[cm]?js)$/.test(base);
}

function compileGlobMatcher(pattern: string): RegExp {
  const isDir = pattern.endsWith("/");
  const body = (isDir ? pattern.slice(0, -1) : pattern).replace(/^\/+/, "");
  const escaped = body
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__DBLSTAR__")
    .replace(/\*/g, "[^/]*")
    .replace(/__DBLSTAR__/g, ".*");
  return new RegExp(`^${escaped}${isDir ? "(?:/.*)?$" : "$"}`);
}

interface IgnoreRule {
  pattern: string;
  regex: RegExp;
  source: "vstackignore" | "config-ignore";
}

function loadIgnoreRules(root: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  const ignorePath = path.join(root, ".vstackignore");
  if (fs.existsSync(ignorePath)) {
    try {
      for (const line of fs.readFileSync(ignorePath, "utf8").split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        rules.push({ pattern: trimmed, regex: compileGlobMatcher(trimmed), source: "vstackignore" });
      }
    } catch { return rules; }
  }
  try {
    for (const pat of loadRepoConfig(root).ignore) {
      rules.push({ pattern: pat, regex: compileGlobMatcher(pat), source: "config-ignore" });
    }
  } catch { return rules; }
  return rules;
}

function isMinifiedJs(rel: string, content: string, lines: number): boolean {
  if (MINIFIED_FILE_PATH.test(rel)) return true;
  if (!/\.[cm]?js$/i.test(rel)) return false;
  if (lines > 0 && content.length / lines > 300) return true;
  for (const line of content.split(/\r?\n/)) if (line.length > 2_500) return true;
  return false;
}

function loadGitTrackedDirs(root: string): Set<string> {
  const trackedDirs = new Set<string>();
  const res = runGitClean(root, ["ls-files", "-z"]);
  if (res.status !== 0) return trackedDirs;
  for (const rel of res.stdout.split("\0")) {
    if (!rel) continue;
    let cur = path.posix.dirname(rel);
    while (cur && cur !== ".") {
      trackedDirs.add(cur);
      cur = path.posix.dirname(cur);
    }
  }
  return trackedDirs;
}

function shouldSkipDirectory(rel: string, name: string, trackedDirs: ReadonlySet<string>, absDir?: string): boolean {
  if (ALWAYS_SKIP_DIRS.has(name)) return true;
  if (rel === ".verification/receipts" || rel === "vendor") return true;
  if (name === "obj" && !trackedDirs.has(rel)) return true;
  if (name === "bin" && !trackedDirs.has(rel)) {
    if (rel !== "bin") return true;
    if (absDir && (fs.existsSync(path.join(absDir, "Debug")) || fs.existsSync(path.join(absDir, "Release")))) return true;
  }
  if (WORKSPACE_BUILD_DIR.test(rel) && !trackedDirs.has(rel)) return true;
  if (SOURCE_TREE_ROOT.test(rel)) return false;
  if (!UNTRACKED_CACHE_SKIP_DIRS.has(name)) return false;
  return !trackedDirs.has(rel);
}

function detectDefaultBranch(root: string): string | undefined {
  const sym = runGitClean(root, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]);
  if (sym.status === 0 && sym.stdout.trim()) return sym.stdout.trim().replace(/^origin\//, "");
  const head = runGitClean(root, ["rev-parse", "--abbrev-ref", "HEAD"]);
  if (head.status === 0 && head.stdout.trim() && head.stdout.trim() !== "HEAD") return head.stdout.trim();
  return undefined;
}

interface DiscoverWalkState {
  root: string;
  specs: readonly LanguagePluginSpec[];
  trackedDirs: ReadonlySet<string>;
  ignoreRules: readonly IgnoreRule[];
  files: ScannedFile[];
  allRelPaths: string[];
  scopeExclusions: ScopeExclusion[];
  archivedDocDirs: Set<string>;
}

function extractEmbeddedFromSpecs(
  rel: string,
  content: string,
  specs: readonly LanguagePluginSpec[],
): { language: Language; content: string } | undefined {
  for (const spec of specs) {
    if (typeof spec.extractEmbeddedScript === "function") {
      const extracted = spec.extractEmbeddedScript(rel, content);
      if (extracted) return extracted;
    }
  }
  return undefined;
}

function readScannedFileEntry(abs: string, rel: string, state: DiscoverWalkState): void {
  let stat: fs.Stats;
  try { stat = fs.lstatSync(abs); } catch { return; }
  if (!stat.isFile() || stat.isSymbolicLink()) return;
  if (stat.size > MAX_FILE_BYTES) {
    state.scopeExclusions.push({ path: rel, reason: "oversized", detail: `${stat.size} bytes > ${MAX_FILE_BYTES}` });
    return;
  }
  let content: string;
  try { content = fs.readFileSync(abs, "utf8"); } catch { return; }
  const lines = content.length === 0 ? 0 : content.split(/\r?\n/).length;
  if (isMinifiedJs(rel, content, lines)) {
    state.scopeExclusions.push({ path: rel, reason: "minified", detail: "exceeds single-line or density threshold" });
    return;
  }
  const sfc = extractEmbeddedFromSpecs(rel, content, state.specs);
  const language = sfc ? sfc.language : detectLanguageFromSpecs(rel, state.specs);
  state.files.push({
    rel, abs, language, isTest: isTestFilePath(rel, state.specs), isWorkflow: isWorkflowPath(rel),
    ...(pathHelpers.isDeclarationStub(rel) ? { isStub: true } : {}),
    content: sfc ? sfc.content : content,
    ...(sfc ? { rawContent: content } : {}),
    lines,
  });
}

function processDirEntry(
  entry: fs.Dirent,
  dir: string,
  state: DiscoverWalkState,
  queues: { subdirs: string[]; prioritySubdirs: string[] },
): void {
  if (!entry.name) return;
  const abs = path.join(dir, entry.name);
  if (abs !== state.root && !abs.startsWith(`${state.root}${path.sep}`)) return;
  const rel = path.relative(state.root, abs).split(path.sep).join("/");
  if (entry.isSymbolicLink()) {
    const isDocSymlink = /^(?:CLAUDE|AGENTS|GEMINI|README)\.md$|^\.(?:claude|agents|cursor|codex)\/|^docs\//i.test(rel);
    if (rel !== "node_modules" && !rel.startsWith("node_modules/") && !isDocSymlink) {
      state.scopeExclusions.push({ path: rel, reason: "symlink", detail: "symlinked path not followed" });
    }
    return;
  }
  if (entry.isDirectory()) {
    if (entry.name === "node_modules" && state.trackedDirs.has(rel)) {
      state.scopeExclusions.push({ path: rel, reason: "skipped-tracked-dir", detail: "git-tracked node_modules directory" });
      return;
    }
    if (shouldSkipDirectory(rel, entry.name, state.trackedDirs, abs)) return;
    const ignored = state.ignoreRules.find((r) => r.regex.test(rel));
    if (ignored) { state.scopeExclusions.push({ path: rel, reason: ignored.source, detail: `matched '${ignored.pattern}'` }); return; }
    if (PRIORITY_DIRS.has(entry.name)) queues.prioritySubdirs.push(abs);
    else queues.subdirs.push(abs);
    return;
  }
  if (!entry.isFile()) return;
  if (ARCHIVED_DOCS_PATH.test(rel)) {
    if (detectLanguageFromSpecs(rel, state.specs) !== undefined) {
      const rootDir = (ARCHIVED_DOCS_PATH.exec(rel)?.[0] ?? rel).replace(/\/+$/, "");
      if (!state.archivedDocDirs.has(rootDir)) {
        state.archivedDocDirs.add(rootDir);
        state.scopeExclusions.push({ path: rootDir, reason: "skipped-tracked-dir", detail: "code under archived docs path" });
      }
    }
    return;
  }
  const ignored = state.ignoreRules.find((r) => r.regex.test(rel));
  if (ignored) { state.scopeExclusions.push({ path: rel, reason: ignored.source, detail: `matched '${ignored.pattern}'` }); return; }
  state.allRelPaths.push(rel);
  if (shouldReadText(rel, state.specs)) readScannedFileEntry(abs, rel, state);
}

function finalizeDiscoveredMetadata(files: ScannedFile[]): Language[] {
  const csTestProjDirs = new Set<string>();
  for (const file of files) {
    if (file.rel.toLowerCase().endsWith(".csproj") && /<IsTestProject>\s*true\s*<\/IsTestProject>/i.test(file.content)) {
      const dir = path.posix.dirname(file.rel);
      csTestProjDirs.add(dir === "." ? "" : `${dir}/`);
    }
  }
  if (csTestProjDirs.size > 0) {
    for (const file of files) {
      if (file.language === "csharp" && !file.isTest) {
        if ([...csTestProjDirs].some((prefix) => prefix === "" || file.rel.startsWith(prefix))) file.isTest = true;
      }
    }
  }
  const languageSet = new Set<Language>();
  for (const file of files) if (file.language && isHostRepoFile(file.rel) && !HELPER_SCRIPT_ROOT.test(file.rel)) languageSet.add(file.language);
  if (languageSet.size === 0) for (const file of files) if (file.language && isHostRepoFile(file.rel)) languageSet.add(file.language);
  if (languageSet.size === 0) for (const file of files) if (file.language) languageSet.add(file.language);
  return [...languageSet].sort();
}

function mergeSignalExtractors(
  extractors: readonly SignalPluginSpec[],
  input: {
    readonly files: readonly ScannedFile[];
    readonly allRelPaths: readonly string[];
    readonly languages: readonly Language[];
    readonly defaultBranch?: string;
  },
): { signals: ToolSignals; ci: CiExecutionSignals } {
  const signals = createEmptySignals();
  const ci = createEmptyCiSignals();
  for (const extractor of extractors) {
    if (typeof extractor.extract !== "function") continue;
    const out = extractor.extract(input);
    if (out.signals) Object.assign(signals, out.signals);
    if (out.ci) Object.assign(ci, out.ci);
  }
  return { signals, ci };
}

export function discoverRepoWithPlugins(
  repoPath: string,
  options: DiscoverRepoOptions,
): DiscoveredRepo {
  if (!repoPath) throw new Error("Repository path is required.");
  const root = path.resolve(repoPath);
  const state: DiscoverWalkState = {
    root,
    specs: options.languages ?? [],
    trackedDirs: loadGitTrackedDirs(root),
    ignoreRules: loadIgnoreRules(root),
    files: [],
    allRelPaths: [],
    scopeExclusions: [],
    archivedDocDirs: new Set<string>(),
  };
  const stack: string[] = [root];
  let truncated = false;

  while (stack.length > 0) {
    if (state.allRelPaths.length >= MAX_FILES) { truncated = true; break; }
    const dir = stack.pop() ?? "";
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const queues = { subdirs: [] as string[], prioritySubdirs: [] as string[] };
    for (const entry of entries) processDirEntry(entry, dir, state, queues);
    for (let i = queues.subdirs.length - 1; i >= 0; i--) { const n = queues.subdirs[i]; if (n) stack.push(n); }
    for (let i = queues.prioritySubdirs.length - 1; i >= 0; i--) { const n = queues.prioritySubdirs[i]; if (n) stack.push(n); }
  }
  if (truncated) state.scopeExclusions.push({ path: ".", reason: "truncated", detail: `exceeded ${MAX_FILES}-file scan ceiling` });

  const languages = finalizeDiscoveredMetadata(state.files);
  const observedArchetype = inferArchetypeFromFiles(state.files, state.allRelPaths);
  const loadedManifest = loadRungManifest(root, options.validateCommand);
  const archetype = loadedManifest.manifest?.archetype ?? observedArchetype;
  const { signals, ci } = mergeSignalExtractors(options.signals ?? [], {
    files: state.files,
    allRelPaths: state.allRelPaths,
    languages,
    defaultBranch: detectDefaultBranch(root),
  });
  return {
    root, files: state.files, allRelPaths: state.allRelPaths, languages, archetype, observedArchetype,
    manifest: loadedManifest.manifest, manifestError: loadedManifest.error, scopeExclusions: state.scopeExclusions,
    signals, ci,
  };
}
