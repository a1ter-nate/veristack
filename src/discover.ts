import fs from "node:fs";
import path from "node:path";
import { inferArchetypeFromFiles, isHostRepoFile, loadRungManifest } from "./rungs/manifest.ts";
import { extractSignals } from "./rungs/signals.ts";
import type {
  CiExecutionSignals,
  Language,
  RepoArchetype,
  RungManifest,
  ScopeExclusion,
  ToolSignals,
} from "./types.ts";
import { loadRepoConfig } from "./zero-defect/repo-config.ts";

export interface ScannedFile {
  rel: string;
  abs: string;
  language?: Language;
  isTest: boolean;
  isWorkflow: boolean;
  content: string;
  lines: number;
}

export interface DiscoveredRepo {
  root: string;
  files: ScannedFile[];
  allRelPaths: string[];
  languages: Language[];
  archetype: RepoArchetype;
  observedArchetype: RepoArchetype;
  manifest?: RungManifest;
  manifestError?: string;
  scopeExclusions: ScopeExclusion[];
  signals: ToolSignals;
  ci: CiExecutionSignals;
}

const ALWAYS_SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  ".next",
  ".nuxt",
  ".output",
  ".svelte-kit",
  ".vercel",
  ".netlify",
  ".expo",
  ".vite",
  ".parcel-cache",
  ".angular",
  ".turbo",
  ".cache",
  ".venv",
  "venv",
  "__pycache__",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".stryker-tmp",
  "StrykerOutput",
  "TestResults",
  "coverage",
]);

const ROOT_ONLY_SKIP_DIRS = new Set(["dist", "build", "target", "bin", "obj", "vendor"]);

const MAX_FILE_BYTES = 512_000;
const MAX_FILES = 12_000;
const PRIORITY_DIRS = new Set([".github", ".verification", ".circleci", ".husky"]);

export function detectLanguage(rel: string): Language | undefined {
  const lower = rel.toLowerCase();
  if (lower.endsWith(".d.ts")) return undefined;
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".mts") || lower.endsWith(".cts")) {
    return "typescript";
  }
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) {
    return "javascript";
  }
  if (lower.endsWith(".cs")) return "csharp";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".go")) return "go";
  return undefined;
}

export function isTestFilePath(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  const lower = norm.toLowerCase();
  const base = path.posix.basename(lower);
  if (/\.(?:test|spec|e2e|cy|int|integration|contract)\.[cm]?[jt]sx?$/.test(base)) return true;
  if (/(?:^|[-_])tests?\.py$|^test[-_].*\.py$/.test(base)) return true;
  if (/_test\.go$|(?:^|[-_])tests?\.rs$|^test[-_].*\.rs$/.test(base)) return true;
  if (/tests?\.cs$|specs?\.cs$/.test(base)) return true;
  if (/(?:^|\/)[^/]+\.tests\//.test(lower) && lower.endsWith(".cs")) return true;
  if (/^(?:tests?|__tests__|specs?|e2e)\//.test(lower) || /\/(?:tests?|__tests__|specs?|e2e)\//.test(lower)) {
    if (/(?:^|\.)config\.[cm]?[jt]sx?$/.test(base)) return false;
    if (/\/(?:contracts|fixtures|helpers|support|mocks|stubs)\//.test(lower)) return false;
    return detectLanguage(rel) !== undefined;
  }
  return false;
}

function isWorkflowPath(rel: string): boolean {
  const lower = rel.replace(/\\/g, "/").toLowerCase();
  return (
    (lower.startsWith(".github/workflows/") && (lower.endsWith(".yml") || lower.endsWith(".yaml"))) ||
    lower === "azure-pipelines.yml" ||
    lower.endsWith("/azure-pipelines.yml") ||
    lower === ".gitlab-ci.yml" ||
    lower === ".circleci/config.yml" ||
    lower === "bitbucket-pipelines.yml"
  );
}

function shouldReadText(rel: string): boolean {
  const lower = rel.replace(/\\/g, "/").toLowerCase();
  const base = path.posix.basename(lower);
  if (detectLanguage(rel) !== undefined) return true;
  if (isWorkflowPath(rel)) return true;
  if ((lower.endsWith(".yml") || lower.endsWith(".yaml")) && /(?:^|\/)(?:maestro|e2e|mobile-e2e|flows)\//.test(lower)) {
    return true;
  }
  if (lower.endsWith(".vue") || lower.endsWith(".css") || lower.endsWith(".bend")) return true;
  if (lower.endsWith(".sh") || lower.endsWith(".bash")) return true;
  if (lower.endsWith(".sql") && /(?:^|\/)(?:migrations?|supabase|policies|rls|schema)\//.test(lower)) return true;
  if (lower.endsWith(".laws.json") || /(?:^|\/)\.verification\/(?:laws\/|chokepoints\.json|rungs\.json|control-plan\.json|escapes\.json|behavior-changes\.json)/.test(lower)) {
    return true;
  }
  if (base === ".golangci.yml" || base === ".golangci.yaml" || base === "biome.json" || base === "biome.jsonc") return true;
  if (/^\.env\.(?:example|sample|template|dist)$/i.test(base)) return true;
  if (base === "dockerfile" || base.startsWith("dockerfile.")) return true;
  return (
    base === "package.json" ||
    base === "tsconfig.json" ||
    base === "pyproject.toml" ||
    base === "cargo.toml" ||
    base === "go.mod" ||
    base === "codeowners" ||
    base === "agents.md" ||
    base === "claude.md" ||
    base === "gemini.md" ||
    base === ".cursorrules" ||
    base === "copilot-instructions.md" ||
    base === "skill.md" ||
    base === "review.md" ||
    base === "gates.md" ||
    base === "lefthook.yml" ||
    base === ".oxlintrc.json" ||
    base === ".oxlintrc.jsonc" ||
    base === "oxlint.config.ts" ||
    base === "turbo.json" ||
    base === "directory.build.props" ||
    base === "directory.packages.props" ||
    base === ".editorconfig" ||
    base === "stryker-config.json" ||
    base === "clippy.toml" ||
    base === ".clippy.toml" ||
    base === "rustfmt.toml" ||
    base === ".rustfmt.toml" ||
    base === "mutants.toml" ||
    base === "ruff.toml" ||
    base === ".ruff.toml" ||
    base === "mypy.ini" ||
    base === "pyrightconfig.json" ||
    base === "pytest.ini" ||
    base === "control-plan.json" ||
    base === "escapes.json" ||
    base === "knip.json" ||
    base === "knip.jsonc" ||
    base.endsWith(".csproj") ||
    base.endsWith(".tla") ||
    base.endsWith(".qnt") ||
    base.endsWith(".als") ||
    base.endsWith(".dfy") ||
    base.endsWith(".lean") ||
    base.endsWith(".feature") ||
    /^(?:vitest|vite|playwright|cypress|k6)\.config\.[cm]?[jt]s$/.test(base) ||
    /^\.?lighthouserc\.(?:json|ya?ml|[cm]?js)$/.test(base)
  );
}

const ARCHIVED_DOCS_PATH = /^docs\/.*\/(?:data|archive|snapshots|artifacts)\//i;
const MINIFIED_FILE_PATH = /\.(?:min|bundle)\.[cm]?js$/i;

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
      const raw = fs.readFileSync(ignorePath, "utf8");
      for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        rules.push({ pattern: trimmed, regex: compileGlobMatcher(trimmed), source: "vstackignore" });
      }
    } catch {
      return rules;
    }
  }
  try {
    const cfg = loadRepoConfig(root);
    for (const pat of cfg.ignore) {
      rules.push({ pattern: pat, regex: compileGlobMatcher(pat), source: "config-ignore" });
    }
  } catch {
    return rules;
  }
  return rules;
}

function isMinifiedJs(rel: string, content: string, lines: number): boolean {
  if (MINIFIED_FILE_PATH.test(rel)) return true;
  if (!/\.[cm]?js$/i.test(rel)) return false;
  if (lines > 0 && content.length / lines > 300) return true;
  for (const line of content.split(/\r?\n/)) {
    if (line.length > 2_500) return true;
  }
  return false;
}

function isBuildOutputSkipDir(dirRel: string, entryName: string): boolean {
  if (ALWAYS_SKIP_DIRS.has(entryName)) return true;
  if (!ROOT_ONLY_SKIP_DIRS.has(entryName)) return false;
  if (dirRel === entryName) return true;
  if (/^(?:apps|packages|services|crates|libs|templates|lint)\/[^/]+(?:\/[^/]+)?\/(?:dist|build|target|bin|obj|vendor)$/.test(dirRel)) {
    return true;
  }
  return false;
}

export function discoverRepo(repoPath: string): DiscoveredRepo {
  const root = path.resolve(repoPath);
  const ignoreRules = loadIgnoreRules(root);
  const matchIgnore = (rel: string): IgnoreRule | undefined => ignoreRules.find((r) => r.regex.test(rel));
  const files: ScannedFile[] = [];
  const allRelPaths: string[] = [];
  const scopeExclusions: ScopeExclusion[] = [];
  const stack: string[] = [root];
  let truncated = false;

  while (stack.length > 0) {
    if (allRelPaths.length >= MAX_FILES) {
      truncated = true;
      break;
    }
    const dir = stack.pop() ?? "";
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const subdirs: string[] = [];
    const prioritySubdirs: string[] = [];

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (rel === ".verification/receipts") continue;
        if (isBuildOutputSkipDir(rel, entry.name)) continue;
        const ignored = matchIgnore(rel);
        if (ignored) {
          scopeExclusions.push({ path: rel, reason: ignored.source, detail: `matched '${ignored.pattern}'` });
          continue;
        }
        if (PRIORITY_DIRS.has(entry.name)) prioritySubdirs.push(abs);
        else subdirs.push(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      if (ARCHIVED_DOCS_PATH.test(rel)) continue;
      const ignored = matchIgnore(rel);
      if (ignored) {
        scopeExclusions.push({ path: rel, reason: ignored.source, detail: `matched '${ignored.pattern}'` });
        continue;
      }
      allRelPaths.push(rel);
      if (!shouldReadText(rel)) continue;
      let stat: fs.Stats;
      try {
        stat = fs.lstatSync(abs);
      } catch {
        continue;
      }
      if (!stat.isFile() || stat.isSymbolicLink()) continue;
      if (stat.size > MAX_FILE_BYTES) {
        scopeExclusions.push({ path: rel, reason: "oversized", detail: `${stat.size} bytes > ${MAX_FILE_BYTES}` });
        continue;
      }
      let content: string;
      try {
        content = fs.readFileSync(abs, "utf8");
      } catch {
        continue;
      }
      const lines = content.length === 0 ? 0 : content.split(/\r?\n/).length;
      if (isMinifiedJs(rel, content, lines)) {
        scopeExclusions.push({ path: rel, reason: "minified", detail: "exceeds single-line or density threshold" });
        continue;
      }
      const language = detectLanguage(rel);
      files.push({
        rel,
        abs,
        language,
        isTest: isTestFilePath(rel),
        isWorkflow: isWorkflowPath(rel),
        content,
        lines,
      });
    }

    for (let i = subdirs.length - 1; i >= 0; i--) {
      const nextDir = subdirs[i];
      if (nextDir) stack.push(nextDir);
    }
    for (let i = prioritySubdirs.length - 1; i >= 0; i--) {
      const nextDir = prioritySubdirs[i];
      if (nextDir) stack.push(nextDir);
    }
  }

  if (truncated) {
    scopeExclusions.push({ path: ".", reason: "truncated", detail: `exceeded ${MAX_FILES}-file scan ceiling` });
  }

  const languageSet = new Set<Language>();
  for (const file of files) {
    if (file.language && isHostRepoFile(file.rel)) languageSet.add(file.language);
  }
  if (languageSet.size === 0) {
    for (const file of files) {
      if (file.language) languageSet.add(file.language);
    }
  }
  const languages = [...languageSet].sort();

  const observedArchetype = inferArchetypeFromFiles(files, allRelPaths);
  const loadedManifest = loadRungManifest(root);
  const archetype = loadedManifest.manifest?.archetype ?? observedArchetype;
  const { signals, ci } = extractSignals(files, allRelPaths, languages);

  return {
    root,
    files,
    allRelPaths,
    languages,
    archetype,
    observedArchetype,
    manifest: loadedManifest.manifest,
    manifestError: loadedManifest.error,
    scopeExclusions,
    signals,
    ci,
  };
}
