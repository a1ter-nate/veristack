import fs from "node:fs";
import path from "node:path";
import { canStartJsRegex } from "./anti-slop/lexical-mask.ts";
import { runGitClean } from "./rungs/config-audit.ts";
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
  isStub?: boolean;
  content: string;
  rawContent?: string;
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

const UNTRACKED_CACHE_SKIP_DIRS = new Set([
  ".git", "node_modules", ".next", ".nuxt", ".output", ".svelte-kit", ".vercel", ".netlify",
  ".expo", ".vite", ".parcel-cache", ".angular", ".turbo", ".cache", ".venv", "venv",
  "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".stryker-tmp",
  "StrykerOutput", "TestResults", "coverage", "dist", "build", "target", "obj", "vendor",
]);

const MAX_FILE_BYTES = 512_000;
const MAX_FILES = 12_000;
const PRIORITY_DIRS = new Set([".github", ".verification", ".circleci", ".husky"]);

const SOURCE_TREE_ROOT = /^(?:src|packages|services|apps|crates|libs|pkg|internal|cmd)\//i;

export function detectLanguage(rel: string): Language | undefined {
  const lower = rel.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".mts") || lower.endsWith(".cts")) {
    return "typescript";
  }
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) {
    return "javascript";
  }
  if (lower.endsWith(".cs") || lower.endsWith(".csx")) return "csharp";
  if (lower.endsWith(".py") || lower.endsWith(".pyi")) return "python";
  if (lower.endsWith(".rs")) return "rust";
  if (lower.endsWith(".go")) return "go";
  return undefined;
}

export function isDeclarationStub(rel: string): boolean {
  return /\.(?:d\.[cm]?ts|pyi)$/i.test(rel);
}

export function scanSfcScriptSpans(raw: string): Array<{ attrs: string; bodyStart: number; bodyEnd: number }> {
  const spans: Array<{ attrs: string; bodyStart: number; bodyEnd: number }> = [];
  for (let i = 0; i < raw.length; ) {
    if (raw.startsWith("<!--", i)) { const e = raw.indexOf("-->", i + 4); if (e < 0) break; i = e + 3; continue; }
    if (raw[i] === "<" && /^<script\b/i.test(raw.slice(i, i + 8))) {
      let gt = -1; let attrQ = "";
      for (let k = i + 7; k < raw.length; k++) {
        const ac = raw[k] ?? "";
        if (attrQ) { if (ac === attrQ) attrQ = ""; continue; }
        if (ac === '"' || ac === "'") { attrQ = ac; continue; }
        if (ac === ">") { gt = k; break; }
      }
      if (gt < 0) break;
      const attrs = raw.slice(i + 7, gt); const bodyStart = gt + 1;
      let j = bodyStart; let q = ""; let bodyEnd = -1; let closeLen = 0; const tplStack: number[] = [];
      while (j < raw.length) {
        const ch = raw[j] ?? ""; const nx = raw[j + 1] ?? "";
        if (!q) {
          if (tplStack.length > 0) {
            const top = tplStack[tplStack.length - 1] ?? 0;
            if (ch === "{") { tplStack[tplStack.length - 1] = top + 1; j += 1; continue; }
            if (ch === "}") {
              if (top === 0) { tplStack.pop(); q = "`"; j += 1; continue; }
              tplStack[tplStack.length - 1] = top - 1; j += 1; continue;
            }
          }
          if (ch === "/" && nx === "/") { while (j < raw.length && raw[j] !== "\n") j += 1; continue; }
          if (ch === "/" && nx === "*") { const e = raw.indexOf("*/", j + 2); j = e < 0 ? raw.length : e + 2; continue; }
          if (ch === "/" && nx !== "/" && nx !== "*" && canStartJsRegex(raw, j)) {
            let rj = j + 1; let inCls = false; let ok = false;
            while (rj < raw.length && raw[rj] !== "\n" && raw[rj] !== "\r") {
              if (raw[rj] === "\\") { rj += 2; continue; }
              if (raw[rj] === "[") inCls = true;
              else if (raw[rj] === "]") inCls = false;
              else if (raw[rj] === "/" && !inCls) { ok = true; break; }
              rj += 1;
            }
            if (ok) { j = rj + 1; continue; }
          }
          if (ch === "'" && j > bodyStart && /[A-Za-z]/.test(raw[j - 1] ?? "") && /[A-Za-z]/.test(nx)) { j += 1; continue; }
          if (ch === '"' || ch === "'" || ch === "`") { q = ch; j += 1; continue; }
          if (ch === "<" && nx === "/") {
            const cm = /^<\/script\s*>/i.exec(raw.slice(j, j + 16));
            if (cm) { bodyEnd = j; closeLen = cm[0].length; break; }
          }
          j += 1;
        } else {
          if (ch === "\\") { j += 2; continue; }
          if (q === "`" && ch === "$" && nx === "{") { q = ""; tplStack.push(0); j += 2; continue; }
          if (ch === q) q = "";
          j += 1;
        }
      }
      if (bodyEnd < 0) break;
      spans.push({ attrs, bodyStart, bodyEnd }); i = bodyEnd + closeLen; continue;
    }
    i += 1;
  }
  return spans;
}

export function extractSfcScript(rel: string, raw: string): { language: Language; content: string } | undefined {
  const lower = rel.toLowerCase();
  const isAstro = lower.endsWith(".astro");
  if (!isAstro && !lower.endsWith(".vue") && !lower.endsWith(".svelte")) return undefined;
  const out = Array<string>(raw.length).fill(" ");
  for (let i = 0; i < raw.length; i++) if (raw[i] === "\n") out[i] = "\n";
  let foundAny = false;
  if (isAstro) {
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(raw);
    if (fm?.[1]) {
      const start = fm[0].indexOf(fm[1]);
      for (let i = 0; i < fm[1].length; i++) out[start + i] = fm[1][i] ?? " ";
      foundAny = true;
    }
  }
  const spans = scanSfcScriptSpans(raw);
  for (const sp of spans) {
    for (let i = sp.bodyStart; i < sp.bodyEnd; i++) out[i] = raw[i] ?? " ";
    foundAny = true;
  }
  if (!foundAny) return undefined;
  const isTs = isAstro || spans.some((sp) => /\blang\s*=\s*["']tsx?["']/i.test(sp.attrs));
  return { language: isTs ? "typescript" : "javascript", content: out.join("") };
}

export function isTestFilePath(rel: string): boolean {
  const norm = rel.replace(/\\/g, "/");
  const lower = norm.toLowerCase();
  const base = path.posix.basename(lower);
  if (/\.(?:test|spec|e2e|cy|int|integration|contract)\.[cm]?[jt]sx?$/.test(base)) return true;
  if (/(?:^|[-_])tests?\.py$|^test[-_].*\.py$|^conftest\.py$/.test(base)) return true;
  if (/_test\.go$|(?:^|[-_])tests?\.rs$|^test[-_].*\.rs$/.test(base)) return true;
  if (/tests?\.cs$|specs?\.cs$/.test(base)) return true;
  if (/(?:^|\/)[^/]+\.(?:tests?|unittests|integrationtests|specs?)\//.test(lower) && lower.endsWith(".cs")) return true;
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
  if ((lower.endsWith(".yml") || lower.endsWith(".yaml")) && (/(?:^|\/)(?:maestro|e2e|mobile-e2e|flows)\//.test(lower) || /(?:^|\/)\.github\/(?:.+\/)?action\.ya?ml$/.test(lower))) {
    return true;
  }
  if (lower.endsWith(".vue") || lower.endsWith(".svelte") || lower.endsWith(".astro") || lower.endsWith(".css") || lower.endsWith(".bend")) return true;
  if (lower.endsWith(".sh") || lower.endsWith(".bash")) return true;
  if (lower.endsWith(".sql") && (/(?:^|\/)(?:migrations?|supabase|policies|rls|schema|db|sql|flyway)\//.test(lower) || base.endsWith("schema.sql"))) return true;
  if (lower.endsWith(".laws.json") || /(?:^|\/)\.verification\/(?:laws\/|chokepoints\.json|rungs\.json|hooks\.json|control-plan\.json|escapes\.json|behavior-changes\.json)/.test(lower)) {
    return true;
  }
  if (base === ".golangci.yml" || base === ".golangci.yaml" || base === "biome.json" || base === "biome.jsonc") return true;
  if (/^\.env\.(?:example|sample|template|dist)$/i.test(base)) return true;
  if (base === "dockerfile" || base.startsWith("dockerfile.")) return true;
  return (
    base === "package.json" ||
    /^tsconfig(?:\.[^/]+)?\.json$/.test(base) ||
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

const WORKSPACE_BUILD_DIR = /^(?:apps|packages|services|crates|libs)\/[^/]+\/(?:dist|build|coverage|target|obj|\.next|\.nuxt|\.output|\.svelte-kit|\.vite|\.turbo|\.cache|\.stryker-tmp|TestResults|StrykerOutput|__pycache__|\.venv|venv)$/i;
const HELPER_SCRIPT_ROOT = /^\.(?:github|agents|claude|cursor|codex|husky)\//i;

function shouldSkipDirectory(rel: string, name: string, trackedDirs: ReadonlySet<string>): boolean {
  if (name === ".git" || name === "node_modules") return true;
  if (rel === ".verification/receipts") return true;
  if (WORKSPACE_BUILD_DIR.test(rel) && !trackedDirs.has(rel)) return true;
  if (SOURCE_TREE_ROOT.test(rel)) return false;
  if (name === "bin" && /(?:^|\/)(?:obj|bin)$/.test(rel) && !trackedDirs.has(rel)) {
    if (rel === "bin") return false;
    return true;
  }
  if (!UNTRACKED_CACHE_SKIP_DIRS.has(name)) return false;
  if (trackedDirs.has(rel)) return false;
  return true;
}

export function discoverRepo(repoPath: string): DiscoveredRepo {
  const root = path.resolve(repoPath);
  const trackedDirs = loadGitTrackedDirs(root);
  const ignoreRules = loadIgnoreRules(root);
  const matchIgnore = (rel: string): IgnoreRule | undefined => ignoreRules.find((r) => r.regex.test(rel));
  const files: ScannedFile[] = [];
  const allRelPaths: string[] = [];
  const scopeExclusions: ScopeExclusion[] = [];
  const archivedDocDirs = new Set<string>();
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
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (entry.isSymbolicLink()) {
        if (rel !== "node_modules" && !rel.startsWith("node_modules/")) {
          scopeExclusions.push({ path: rel, reason: "symlink", detail: "symlinked path not followed" });
        }
        continue;
      }
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" && trackedDirs.has(rel)) {
          scopeExclusions.push({ path: rel, reason: "skipped-tracked-dir", detail: "git-tracked node_modules directory" });
          continue;
        }
        if (shouldSkipDirectory(rel, entry.name, trackedDirs)) continue;
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
      if (ARCHIVED_DOCS_PATH.test(rel)) {
        if (detectLanguage(rel) !== undefined) {
          const m = ARCHIVED_DOCS_PATH.exec(rel);
          const rootDir = (m?.[0] ?? rel).replace(/\/+$/, "");
          if (!archivedDocDirs.has(rootDir)) {
            archivedDocDirs.add(rootDir);
            scopeExclusions.push({ path: rootDir, reason: "skipped-tracked-dir", detail: "code under archived docs path" });
          }
        }
        continue;
      }
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
      const sfc = extractSfcScript(rel, content);
      const language = sfc ? sfc.language : detectLanguage(rel);
      const effectiveContent = sfc ? sfc.content : content;
      files.push({
        rel,
        abs,
        language,
        isTest: isTestFilePath(rel),
        isWorkflow: isWorkflowPath(rel),
        ...(isDeclarationStub(rel) ? { isStub: true } : {}),
        content: effectiveContent,
        ...(sfc ? { rawContent: content } : {}),
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
        for (const prefix of csTestProjDirs) {
          if (prefix === "" || file.rel.startsWith(prefix)) { file.isTest = true; break; }
        }
      }
    }
  }

  const languageSet = new Set<Language>();
  for (const file of files) if (file.language && isHostRepoFile(file.rel) && !HELPER_SCRIPT_ROOT.test(file.rel)) languageSet.add(file.language);
  if (languageSet.size === 0) for (const file of files) if (file.language && isHostRepoFile(file.rel)) languageSet.add(file.language);
  if (languageSet.size === 0) for (const file of files) if (file.language) languageSet.add(file.language);
  const languages = [...languageSet].sort();
  const observedArchetype = inferArchetypeFromFiles(files, allRelPaths);
  const loadedManifest = loadRungManifest(root);
  const archetype = loadedManifest.manifest?.archetype ?? observedArchetype;
  const { signals, ci } = extractSignals(files, allRelPaths, languages);
  return { root, files, allRelPaths, languages, archetype, observedArchetype, manifest: loadedManifest.manifest, manifestError: loadedManifest.error, scopeExclusions, signals, ci };
}
