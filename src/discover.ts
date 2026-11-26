import fs from "node:fs";
import path from "node:path";
import { extractSignals } from "./rungs/signals.ts";
import type { CiExecutionSignals, Language, RepoArchetype, ToolSignals } from "./types.ts";
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
  signals: ToolSignals;
  ci: CiExecutionSignals;
}

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
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
  "target",
  "bin",
  "obj",
  ".stryker-tmp",
  "StrykerOutput",
  "TestResults",
  "vendor",
]);

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
  if (lower.endsWith(".laws.json") || /(?:^|\/)\.verification\/(?:laws\/|chokepoints\.json)/.test(lower)) return true;
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
    base.endsWith(".csproj") ||
    base.endsWith(".tla") ||
    base.endsWith(".qnt") ||
    base.endsWith(".als") ||
    base.endsWith(".dfy") ||
    base.endsWith(".lean") ||
    base.endsWith(".feature") ||
    base === "knip.json" ||
    base === "knip.jsonc" ||
    /^(?:vitest|vite|playwright|cypress|k6)\.config\.[cm]?[jt]s$/.test(base) ||
    /^\.?lighthouserc\.(?:json|ya?ml|[cm]?js)$/.test(base)
  );
}

function readSafe(abs: string): string | undefined {
  try {
    const stat = fs.lstatSync(abs);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_FILE_BYTES) return undefined;
    return fs.readFileSync(abs, "utf8");
  } catch {
    return undefined;
  }
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

function loadIgnoreMatchers(root: string): RegExp[] {
  const matchers: RegExp[] = [];
  const ignorePath = path.join(root, ".vstackignore");
  if (fs.existsSync(ignorePath)) {
    try {
      const raw = fs.readFileSync(ignorePath, "utf8");
      for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        matchers.push(compileGlobMatcher(trimmed));
      }
    } catch {
      return matchers;
    }
  }
  try {
    const cfg = loadRepoConfig(root);
    for (const pat of cfg.ignore) {
      matchers.push(compileGlobMatcher(pat));
    }
  } catch {
    return matchers;
  }
  return matchers;
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

export function discoverRepo(repoPath: string): DiscoveredRepo {
  const root = path.resolve(repoPath);
  const ignoreMatchers = loadIgnoreMatchers(root);
  const isIgnored = (rel: string): boolean => ignoreMatchers.some((re) => re.test(rel));
  const files: ScannedFile[] = [];
  const allRelPaths: string[] = [];
  const stack: string[] = [root];

  while (stack.length > 0 && allRelPaths.length < MAX_FILES) {
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
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        const dirRel = path.relative(root, path.join(dir, entry.name)).split(path.sep).join("/");
        if (isIgnored(dirRel)) continue;
        const fullDir = path.join(dir, entry.name);
        if (PRIORITY_DIRS.has(entry.name)) prioritySubdirs.push(fullDir);
        else subdirs.push(fullDir);
        continue;
      }
      if (!entry.isFile()) continue;
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (ARCHIVED_DOCS_PATH.test(rel) || isIgnored(rel)) continue;
      allRelPaths.push(rel);
      if (!shouldReadText(rel)) continue;
      const content = readSafe(abs);
      if (content === undefined) continue;
      const lines = content.length === 0 ? 0 : content.split(/\r?\n/).length;
      if (isMinifiedJs(rel, content, lines)) continue;
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

  const languageSet = new Set<Language>();
  for (const file of files) {
    if (file.language) languageSet.add(file.language);
  }
  const languages = [...languageSet].sort();

  const lowerPaths = allRelPaths.map((p) => p.toLowerCase());
  const manifestText = files
    .filter((f) => !f.isTest && !f.isWorkflow && !f.language && !f.rel.toLowerCase().endsWith(".md"))
    .map((f) => f.content)
    .join("\n");

  const hasReactOrUi =
    /(?:["'](?:react|next|vue|svelte|@angular\/core|solid-js)["']|\b(?:react-dom|next\.config)\b)/i.test(manifestText) ||
    lowerPaths.some((p) => p.endsWith(".tsx") || p.endsWith(".jsx") || p.endsWith(".vue") || p.endsWith(".svelte"));
  const hasBackendService =
    /\b(?:express|fastify|hono|nestjs|koa|fastapi|django|flask|actix-web|axum|gin-gonic|microsoft\.aspnetcore)\b/i.test(
      manifestText,
    ) ||
    files.some((f) => f.language === "csharp" && !f.isTest && /\bWebApplication\.CreateBuilder\b/.test(f.content)) ||
    lowerPaths.some((p) => p.includes("dockerfile") || p.includes("controllers/") || p.includes("routes/"));

  let archetype: RepoArchetype = "library";
  if (hasReactOrUi && hasBackendService) archetype = "fullstack";
  else if (hasReactOrUi) archetype = "frontend";
  else if (hasBackendService) archetype = "service";

  const { signals, ci } = extractSignals(files, allRelPaths, languages);

  return { root, files, allRelPaths, languages, archetype, signals, ci };
}
