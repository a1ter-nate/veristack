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
const PRIORITY_DIRS = new Set([".github", ".verification", ".circleci", ".husky", ".githooks", "ci", ".azure-pipelines", ".azuredevops"]);

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

function findSfcTagClose(raw: string, start: number): number {
  let attrQ = "";
  for (let k = start; k < raw.length; k++) {
    const ac = raw[k] ?? "";
    if (attrQ) { if (ac === attrQ) attrQ = ""; continue; }
    if (ac === '"' || ac === "'") { attrQ = ac; continue; }
    if (ac === ">") return k;
  }
  return -1;
}

function skipJsRegexLiteral(raw: string, start: number): number {
  let rj = start + 1;
  let inCls = false;
  while (rj < raw.length && raw[rj] !== "\n" && raw[rj] !== "\r") {
    if (raw[rj] === "\\") { rj += 2; continue; }
    if (raw[rj] === "[") inCls = true;
    else if (raw[rj] === "]") inCls = false;
    else if (raw[rj] === "/" && !inCls) return rj + 1;
    rj += 1;
  }
  return -1;
}

function findSfcScriptEnd(raw: string, bodyStart: number): { bodyEnd: number; closeLen: number } {
  if (!raw) return { bodyEnd: -1, closeLen: 0 };
  if (bodyStart >= raw.length) return { bodyEnd: -1, closeLen: 0 };
  let j = bodyStart;
  let q = "";
  const tplStack: number[] = [];
  while (j < raw.length) {
    const ch = raw[j] ?? "";
    const nx = raw[j + 1] ?? "";
    if (q) {
      if (ch === "\\") { j += 2; continue; }
      if (q === "`" && ch === "$" && nx === "{") { q = ""; tplStack.push(0); j += 2; continue; }
      if (ch === q) q = "";
      j += 1;
      continue;
    }
    if (tplStack.length > 0 && (ch === "{" || ch === "}")) {
      const top = tplStack[tplStack.length - 1] ?? 0;
      if (ch === "{") tplStack[tplStack.length - 1] = top + 1;
      else if (top === 0) { tplStack.pop(); q = "`"; }
      else tplStack[tplStack.length - 1] = top - 1;
      j += 1;
      continue;
    }
    if (ch === "/" && nx === "/") { while (j < raw.length && raw[j] !== "\n") j += 1; continue; }
    if (ch === "/" && nx === "*") { const e = raw.indexOf("*/", j + 2); j = e < 0 ? raw.length : e + 2; continue; }
    if (ch === "/" && nx !== "/" && nx !== "*" && canStartJsRegex(raw, j)) {
      const afterRegex = skipJsRegexLiteral(raw, j);
      if (afterRegex >= 0) { j = afterRegex; continue; }
    }
    if (ch === "'" && j > bodyStart && /[A-Za-z]/.test(raw[j - 1] ?? "") && /[A-Za-z]/.test(nx)) { j += 1; continue; }
    if (ch === '"' || ch === "'" || ch === "`") { q = ch; j += 1; continue; }
    if (ch === "<" && nx === "/") {
      const cm = /^<\/script\s*>/i.exec(raw.slice(j, j + 16));
      if (cm) return { bodyEnd: j, closeLen: cm[0].length };
    }
    j += 1;
  }
  return { bodyEnd: -1, closeLen: 0 };
}

export function scanSfcScriptSpans(raw: string): Array<{ attrs: string; bodyStart: number; bodyEnd: number }> {
  const spans: Array<{ attrs: string; bodyStart: number; bodyEnd: number }> = [];
  if (!raw) return spans;
  for (let i = 0; i < raw.length; ) {
    if (raw.startsWith("<!--", i)) { const e = raw.indexOf("-->", i + 4); if (e < 0) break; i = e + 3; continue; }
    if (raw[i] === "<" && /^<script\b/i.test(raw.slice(i, i + 8))) {
      const gt = findSfcTagClose(raw, i + 7);
      if (gt < 0) break;
      const attrs = raw.slice(i + 7, gt);
      const bodyStart = gt + 1;
      const { bodyEnd, closeLen } = findSfcScriptEnd(raw, bodyStart);
      if (bodyEnd < 0) break;
      spans.push({ attrs, bodyStart, bodyEnd });
      i = bodyEnd + closeLen;
      continue;
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
  if (/(?:^|[-_])tests?\.(?:sh|bash)$/.test(base) || (/^(?:tests?|__tests__)\//.test(lower) && /\.(?:sh|bash)$/.test(base))) return true;
  if (/^(?:tests?|__tests__|specs?|e2e)\//.test(lower) || /\/(?:tests?|__tests__|specs?|e2e)\//.test(lower)) {
    if (/(?:^|\.)config\.[cm]?[jt]sx?$/.test(base)) return false;
    if (/\/(?:contracts|fixtures|helpers|support|mocks|stubs)\//.test(lower)) return false;
    return detectLanguage(rel) !== undefined;
  }
  return false;
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

function shouldReadText(rel: string): boolean {
  const lower = rel.replace(/\\/g, "/").toLowerCase();
  const base = path.posix.basename(lower);
  if (detectLanguage(rel) !== undefined || isWorkflowPath(rel) || READ_TEXT_BASENAMES.has(base)) return true;
  if ((lower.endsWith(".yml") || lower.endsWith(".yaml")) && (/(?:^|\/)(?:maestro|e2e|mobile-e2e|flows)\//.test(lower) || /(?:^|\/)\.github\/(?:.+\/)?action\.ya?ml$/.test(lower))) return true;
  if (/\.(?:vue|svelte|astro|css|bend|sh|bash|csproj|tla|qnt|als|dfy|lean|feature)$/.test(lower) || /^scripts\/[a-z0-9_.-]+$/.test(lower)) return true;
  if (lower.endsWith(".sql") && (/(?:^|\/)(?:migrations?|supabase|policies|rls|schema|db|sql|flyway)\//.test(lower) || base.endsWith("schema.sql"))) return true;
  if (lower.endsWith(".laws.json") || /(?:^|\/)\.verification\/(?:laws\/|chokepoints\.json|rungs\.json|hooks\.json|control-plan\.json|escapes\.json|behavior-changes\.json)/.test(lower)) return true;
  if (/^\.env\.(?:example|sample|template|dist)$/i.test(base) || base === "dockerfile" || base.startsWith("dockerfile.")) return true;
  return /^tsconfig(?:\.[^/]+)?\.json$/.test(base) || /^(?:vitest|vite|playwright|cypress|k6)\.config\.[cm]?[jt]s$/.test(base) || /^\.?lighthouserc\.(?:json|ya?ml|[cm]?js)$/.test(base);
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

const ALWAYS_SKIP_DIRS = new Set([".git", "node_modules", ".repospec", ".runtime"]);
const WORKSPACE_BUILD_DIR = /^(?:apps|packages|services|crates|libs)\/[^/]+\/(?:dist|build|coverage|target|obj|bin|\.next|\.nuxt|\.output|\.svelte-kit|\.vite|\.turbo|\.cache|\.stryker-tmp|TestResults|StrykerOutput|__pycache__|\.venv|venv)$/i;
const HELPER_SCRIPT_ROOT = /^\.(?:github|agents|claude|cursor|codex|husky)\//i;

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
  if (trackedDirs.has(rel)) return false;
  return true;
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
  trackedDirs: ReadonlySet<string>;
  ignoreRules: readonly IgnoreRule[];
  files: ScannedFile[];
  allRelPaths: string[];
  scopeExclusions: ScopeExclusion[];
  archivedDocDirs: Set<string>;
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
  const sfc = extractSfcScript(rel, content);
  const language = sfc ? sfc.language : detectLanguage(rel);
  state.files.push({
    rel, abs, language, isTest: isTestFilePath(rel), isWorkflow: isWorkflowPath(rel),
    ...(isDeclarationStub(rel) ? { isStub: true } : {}),
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
    if (detectLanguage(rel) !== undefined) {
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
  if (shouldReadText(rel)) readScannedFileEntry(abs, rel, state);
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

export function discoverRepo(repoPath: string): DiscoveredRepo {
  if (!repoPath) throw new Error("Repository path is required.");
  const root = path.resolve(repoPath);
  if (!root) throw new Error("Resolved repository root is required.");
  const state: DiscoverWalkState = {
    root,
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
  const loadedManifest = loadRungManifest(root);
  const archetype = loadedManifest.manifest?.archetype ?? observedArchetype;
  const { signals, ci } = extractSignals(state.files, state.allRelPaths, languages, detectDefaultBranch(root));
  return { root, files: state.files, allRelPaths: state.allRelPaths, languages, archetype, observedArchetype, manifest: loadedManifest.manifest, manifestError: loadedManifest.error, scopeExclusions: state.scopeExclusions, signals, ci };
}
