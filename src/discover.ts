import fs from "node:fs";
import path from "node:path";
import type { Language, RepoArchetype, ToolSignals } from "./types.ts";

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
}

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
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
const MAX_FILES = 4_000;

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
  if (/_test\.go$|_tests?\.rs$/.test(base)) return true;
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
    lower.endsWith("/azure-pipelines.yml")
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
    /^(?:vitest|vite)\.config\.[cm]?[jt]s$/.test(base)
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

function loadIgnoreMatchers(root: string): RegExp[] {
  const ignorePath = path.join(root, ".vstackignore");
  if (!fs.existsSync(ignorePath)) return [];
  let raw = "";
  try {
    raw = fs.readFileSync(ignorePath, "utf8");
  } catch {
    return [];
  }
  const matchers: RegExp[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const isDir = trimmed.endsWith("/");
    const body = (isDir ? trimmed.slice(0, -1) : trimmed).replace(/^\/+/, "");
    const escaped = body
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*\*/g, "__DBLSTAR__")
      .replace(/\*/g, "[^/]*")
      .replace(/__DBLSTAR__/g, ".*");
    matchers.push(new RegExp(`^${escaped}${isDir ? "(?:/.*)?$" : "$"}`));
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
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        const dirRel = path.relative(root, path.join(dir, entry.name)).split(path.sep).join("/");
        if (isIgnored(dirRel)) continue;
        stack.push(path.join(dir, entry.name));
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
  }

  const languageSet = new Set<Language>();
  for (const file of files) {
    if (file.language) languageSet.add(file.language);
  }
  const languages = [...languageSet].sort();

  const lowerPaths = allRelPaths.map((p) => p.toLowerCase());
  const allText = files.map((f) => f.content).join("\n");
  const nonDocText = files
    .filter((f) => !f.rel.toLowerCase().endsWith(".md"))
    .map((f) => f.content)
    .join("\n");
  const configText = files
    .filter((f) => (!f.language && !f.rel.toLowerCase().endsWith(".md")) || f.rel.includes("config") || f.isWorkflow)
    .map((f) => f.content)
    .join("\n");

  const hasReactOrUi =
    /\b(?:react|next|vue|svelte|@angular\/core|solid-js)\b/i.test(configText) ||
    lowerPaths.some((p) => p.endsWith(".tsx") || p.endsWith(".jsx") || p.endsWith(".vue") || p.endsWith(".svelte"));
  const hasBackendService =
    /\b(?:express|fastify|hono|nestjs|koa|fastapi|django|flask|actix-web|axum|gin-gonic|microsoft\.aspnetcore)\b/i.test(
      configText,
    ) ||
    files.some((f) => f.language === "csharp" && !f.isTest && /\bWebApplication\.CreateBuilder\b/.test(f.content)) ||
    lowerPaths.some((p) => p.includes("dockerfile") || p.includes("controllers/") || p.includes("routes/"));

  let archetype: RepoArchetype = "library";
  if (hasReactOrUi && hasBackendService) archetype = "fullstack";
  else if (hasReactOrUi) archetype = "frontend";
  else if (hasBackendService) archetype = "service";

  const hasPath = (re: RegExp): boolean => lowerPaths.some((p) => re.test(p));
  const hasAny = (re: RegExp): boolean => re.test(allText);

  const signals: ToolSignals = {
    hasFormatter:
      hasPath(/prettier|oxfmt|\.editorconfig|rustfmt|ruff/) ||
      /\b(?:prettier|oxfmt|biome|ruff format|\[tool\.ruff\]|dotnet format|gofmt|rustfmt)\b/i.test(configText),
    hasLinter:
      hasPath(/eslint|oxlint|biome|ruff|clippy|golangci|directory\.build\.props/) ||
      /\b(?:eslint|oxlint|biome|ruff|clippy|golangci-lint|roslyn|AnalysisLevel|VStack\.Analyzers)\b/i.test(configText),
    hasOxlint: hasPath(/oxlint/) || /\boxlint\b/i.test(configText),
    hasAntiSlop: hasAny(/anti-slop|dmmulroy\/anti-slop/i),
    hasLandmines: hasAny(/@interfere\/landmines|landmines-testing|landmines\//i),
    hasGoInternal: hasAny(/oxlint-plugin-go-internal/i),
    hasDeslopPlease: hasPath(/\.deslop-please\.allow/) || hasAny(/deslop-please/i),
    hasDesloppify: hasAny(/\bdesloppify\b/i),
    hasStrictTypes:
      /"strict"\s*:\s*true/.test(configText) ||
      /<Nullable>enable<\/Nullable>/i.test(configText) ||
      languages.includes("rust") ||
      languages.includes("go") ||
      /\b(?:mypy|pyright)\b/i.test(configText),
    hasTsgo: hasAny(/\btsgo\b|@typescript\/native-preview/i),
    hasKnipOrDeadCode:
      hasPath(/knip/) || /\bknip\b|CS0162|IDE0051|dead_code/i.test(allText),
    hasJscpd: hasPath(/jscpd/) || /\bjscpd\b/i.test(configText),
    hasArchFitness:
      hasAny(/dependency-cruiser|archunit|netarchtest|import-linter|deptrac|packwerk|turbo\s+boundaries/i) ||
      hasPath(/check-boundaries|arch-fitness/),
    hasPreCommitHook:
      hasPath(/lefthook|\.husky\/|\.pre-commit-config|git-hooks\/pre-commit/) ||
      /core\.hooksPath/.test(configText),
    hasCodeowners: hasPath(/(?:^|\/)codeowners$/),
    hasReviewMd: hasPath(/(?:^|\/)review\.md$/),
    hasAgentsMd: hasPath(/(?:^|\/)(?:agents|claude)\.md$/),
    hasPbt: hasAny(/\b(?:fast-check|fc\.property|hypothesis|fscheck|proptest|quickcheck)\b/i),
    hasMbt: hasAny(
      /\b(?:fc\.commands|RuleBasedStateMachine|modelRun|PropEr|stateright|FsCheck\.Experimental|ToProperty\s*\(\s*\)\s*\.Check|StateMachine|proptest_state_machine|ReferenceStateMachine|state_machine_test!)\b/i,
    ),
    hasContractTool: hasAny(/\b(?:@pact-foundation|pactnet|schemathesis|openapi|asyncapi|buf\.yaml)\b/i),
    hasComponentUiTool: hasAny(/@testing-library|playwright\/experimental-ct|storybook/i),
    hasMsw: hasAny(/\b(?:msw|setupServer|setupWorker)\b/),
    hasMswStrict: /onUnhandledRequest\s*:\s*["']error["']/.test(allText),
    hasTestcontainersOrRealDb: hasAny(
      /\b(?:testcontainers|UseNpgsql|UseSqlServer|pglite|postgres:|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|firebase-emulator)\b/i,
    ),
    hasMigrationTest: hasAny(/\b(?:MigrateAsync|MigrationBuilder|alembic|flyway|prisma migrate)\b/i),
    hasBusDlqTest: hasAny(/\b(?:DeadLetter|MaxDeliveryCount|ServiceBusClient|RabbitMQ|Kafka)\b/i),
    hasDst: hasAny(/\b(?:turmoil|antithesis|deterministic.simulation|virtualClock)\b/i),
    hasDryRun: hasAny(/--dry-run|terraform plan|ansible.*--check/i),
    hasMutationTool: hasAny(/\b(?:stryker|mutmut|cargo-mutants|mutants\.toml|pitest)\b/i) || hasPath(/mutants\.toml|stryker-config\.json/),
    hasFormalTool:
      hasPath(/\.(?:tla|qnt|als|dfy|lean)$|formal_model_check/) ||
      /\b(?:everystate|z3-solver|Microsoft\.Z3|z3::|kani|verus|stateright|loom|shuttle|quint|dafny|tlc|crosshair)\b/i.test(
        nonDocText,
      ),
    hasFuzzTool: hasAny(/\b(?:cargo-fuzz|libFuzzer|jazzer|atheris|fuzzTest)\b/i),
    hasBombadil: hasAny(/\bbombadil\b/i),
    hasVisualTool: hasAny(/\b(?:toHaveScreenshot|chromatic|percy|argos|ui-diff)\b/i),
    hasPerfOrLoadTool: hasAny(/\b(?:k6|BenchmarkDotNet|web-vitals|lighthouse|performance\.mark)\b/i),
    hasE2eTool: hasAny(/\b(?:@playwright\/test|playwright|cypress|selenium|puppeteer)\b/i),
    hasProdTelemetryOrCanary: hasAny(/\b(?:opentelemetry|launchdarkly|canary|goreplay|chaos-mesh|synthetic)\b/i),
    hasDiffSelection: hasAny(/\b(?:testscope|--changed|--affected|affected-projects)\b/i),
  };

  return { root, files, allRelPaths, languages, archetype, signals };
}
