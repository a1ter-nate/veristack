import path from "node:path";
import type { ScannedFile } from "../discover.ts";
import type { CiExecutionSignals, Language, ToolSignals } from "../types.ts";

const MANIFEST_BASENAMES = new Set([
  "package.json",
  "cargo.toml",
  "pyproject.toml",
  "go.mod",
  "directory.build.props",
  "directory.packages.props",
]);

function isManifestFile(rel: string): boolean {
  const base = path.posix.basename(rel.replace(/\\/g, "/").toLowerCase());
  return MANIFEST_BASENAMES.has(base) || base.endsWith(".csproj");
}

function isConfigFile(file: ScannedFile): boolean {
  const lower = file.rel.replace(/\\/g, "/").toLowerCase();
  const base = path.posix.basename(lower);
  if (file.isWorkflow || isManifestFile(file.rel)) return true;
  if (lower.endsWith(".md")) return false;
  if (!file.language) return true;
  return (
    /(?:^|\/)(?:vitest|vite|playwright|jest|oxlint|eslint|stryker|k6|biome|tailwind|next|nuxt|webpack|rollup)\.config\.[cm]?[jt]s$/.test(
      lower,
    ) ||
    base === "oxlint.config.ts" ||
    lower.startsWith(".verification/")
  );
}

function stripCodeStringsAndComments(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:\\])\/\/[^\n]*/g, "$1 ")
    .replace(/(^|\s)#[^\n]*/g, "$1 ")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``");
}

function parsePackageScripts(files: readonly ScannedFile[]): Map<string, string> {
  const scripts = new Map<string, string>();
  for (const file of files) {
    if (path.posix.basename(file.rel).toLowerCase() !== "package.json") continue;
    try {
      const parsed = JSON.parse(file.content) as { scripts?: Record<string, unknown> };
      if (!parsed.scripts || typeof parsed.scripts !== "object") continue;
      for (const [name, cmd] of Object.entries(parsed.scripts)) {
        if (typeof cmd === "string" && cmd.trim().length > 0 && !scripts.has(name)) {
          scripts.set(name, cmd);
        }
      }
    } catch {
      continue;
    }
  }
  return scripts;
}

function collectReferencedScriptNames(text: string): string[] {
  const names: string[] = [];
  const runRe = /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?([a-zA-Z0-9:_-]+)/g;
  for (const match of text.matchAll(runRe)) {
    const candidate = match[1];
    if (candidate && candidate !== "install" && candidate !== "ci" && candidate !== "exec" && candidate !== "dlx") {
      names.push(candidate);
    }
  }
  return names;
}

function buildEffectiveCiText(files: readonly ScannedFile[]): {
  hasCiWorkflows: boolean;
  workflowFiles: string[];
  effectiveCiText: string;
} {
  const workflows = files.filter((f) => f.isWorkflow);
  if (workflows.length === 0) {
    return { hasCiWorkflows: false, workflowFiles: [], effectiveCiText: "" };
  }

  const pkgScripts = parsePackageScripts(files);
  const chunks: string[] = workflows.map((w) => w.content);
  const visitedScripts = new Set<string>();
  let frontier = chunks.join("\n");

  for (let depth = 0; depth < 4; depth++) {
    const nextChunks: string[] = [];
    for (const name of collectReferencedScriptNames(frontier)) {
      if (visitedScripts.has(name)) continue;
      visitedScripts.add(name);
      const body = pkgScripts.get(name);
      if (body) {
        chunks.push(body);
        nextChunks.push(body);
      }
    }
    if (nextChunks.length === 0) break;
    frontier = nextChunks.join("\n");
  }

  const combinedSoFar = chunks.join("\n");
  const scriptFileRe = /\b(?:node|bun|tsx|bash|sh|python3?)\s+([a-zA-Z0-9._/-]+\.(?:[cm]?[jt]s|sh|py))\b/g;
  const fileByRel = new Map(files.map((f) => [f.rel.replace(/\\/g, "/"), f]));
  const seenScriptFiles = new Set<string>();

  for (const match of combinedSoFar.matchAll(scriptFileRe)) {
    const rel = (match[1] ?? "").replace(/^\.\//, "");
    if (!rel || seenScriptFiles.has(rel)) continue;
    if (!/^(?:scripts|tools|\.github)\//.test(rel)) continue;
    seenScriptFiles.add(rel);
    const hit = fileByRel.get(rel);
    if (hit) chunks.push(hit.content);
  }

  return {
    hasCiWorkflows: true,
    workflowFiles: workflows.map((w) => w.rel).sort(),
    effectiveCiText: chunks.join("\n"),
  };
}

export function extractSignals(
  files: readonly ScannedFile[],
  allRelPaths: readonly string[],
  languages: readonly Language[],
): { signals: ToolSignals; ci: CiExecutionSignals } {
  const lowerPaths = allRelPaths.map((p) => p.toLowerCase());
  const hasPath = (re: RegExp): boolean => lowerPaths.some((p) => re.test(p));

  const manifestText = files
    .filter((f) => isManifestFile(f.rel))
    .map((f) => f.content)
    .join("\n");

  const configText = files
    .filter((f) => isConfigFile(f))
    .map((f) => f.content)
    .join("\n");

  const testFiles = files.filter((f) => f.isTest);
  const rawTestText = testFiles.map((f) => f.content).join("\n");
  const codeTestText = testFiles.map((f) => stripCodeStringsAndComments(f.content)).join("\n");

  const testImportLines = testFiles
    .flatMap((f) => f.content.split(/\r?\n/))
    .filter((line) => /^\s*(?:import|from|use|using|require\s*\(|const\s+\w+\s*=\s*require\()/.test(line))
    .join("\n");

  const prodImportLines = files
    .filter((f) => f.language && !f.isTest && !f.rel.startsWith("src/rungs/"))
    .flatMap((f) => f.content.split(/\r?\n/))
    .filter((line) => /^\s*(?:import|from|use|using)\b/.test(line))
    .join("\n");

  const { hasCiWorkflows, workflowFiles, effectiveCiText } = buildEffectiveCiText(files);
  const configAndCi = `${configText}\n${effectiveCiText}`;
  const manifestAndConfig = `${manifestText}\n${configText}`;
  const testImportAndManifest = `${manifestText}\n${testImportLines}`;
  const testCodeAndManifest = `${manifestText}\n${codeTestText}`;

  const hasFormatter =
    hasPath(/(?:^|\/)(?:\.?prettier|oxfmt|\.editorconfig|rustfmt\.toml|\.rustfmt\.toml|biome\.jsonc?|ruff\.toml|\.ruff\.toml)/) ||
    /\b(?:prettier|oxfmt|biome|ruff\s+format|\[tool\.ruff\]|dotnet\s+format|gofmt|rustfmt|cargo\s+fmt)\b/i.test(configAndCi);

  const hasOxlint = hasPath(/(?:^|\/)(?:\.oxlintrc\.jsonc?|oxlint\.config\.[cm]?[jt]s)$/) || /\boxlint\b/i.test(configAndCi);

  const hasLinter =
    hasOxlint ||
    hasPath(/(?:^|\/)(?:\.?eslint|biome\.jsonc?|ruff\.toml|\.ruff\.toml|clippy\.toml|\.clippy\.toml|\.golangci\.ya?ml|directory\.build\.props)/) ||
    /\b(?:eslint|oxlint|biome|ruff\s+check|clippy|golangci-lint|roslyn|AnalysisLevel|VStack\.Analyzers|veristack|vstack(?:\.mjs)?\s+(?:scan|no-comments))\b/i.test(
      configAndCi,
    );

  const hasVeristackGate =
    /\b(?:veristack|vstack(?:\.mjs)?\s+scan|cli\.ts\s+scan|lint\/index\.mjs)\b/i.test(configAndCi) ||
    hasPath(/(?:^|\/)lint\/index\.mjs$/);

  const hasAntiSlop =
    /\b(?:anti-slop|dmmulroy\/anti-slop|VStack\.Analyzers)\b/i.test(configAndCi) || hasVeristackGate;

  const hasLandmines =
    /@interfere\/landmines|landmines-testing|\blandmines\//i.test(configAndCi) || hasVeristackGate;

  const hasGoInternal =
    /\boxlint-plugin-go-internal\b/i.test(configAndCi) ||
    hasPath(/(?:^|\/)lint\/index\.mjs$/);

  const hasDeslopPlease = hasPath(/\.deslop-please\.allow/) || /\bdeslop-please\b/i.test(configAndCi);
  const hasDesloppify = /\bdesloppify\b/i.test(configAndCi);

  const hasStrictTypes =
    /"strict"\s*:\s*true/.test(configText) ||
    /<Nullable>enable<\/Nullable>/i.test(manifestAndConfig) ||
    languages.includes("rust") ||
    languages.includes("go") ||
    /\b(?:mypy|pyright)\b/i.test(configAndCi);

  const hasTsgo = /\btsgo\b|@typescript\/native-preview/i.test(configAndCi);

  const hasKnipOrDeadCode =
    hasPath(/(?:^|\/)knip\.jsonc?$/) ||
    /\bknip\b|"noUnusedLocals"\s*:\s*true|CS0162|IDE0051|dead_code|\bclippy\b|\bruff\s+check\b|\bgo\s+vet\b/i.test(
      configAndCi,
    );

  const hasJscpd = hasPath(/jscpd/) || /\bjscpd\b/i.test(configAndCi);

  const hasArchFitness =
    /\b(?:dependency-cruiser|archunit|netarchtest|import-linter|deptrac|packwerk|turbo\s+boundaries|check-max-lines)\b/i.test(
      `${configAndCi}\n${testImportLines}`,
    ) ||
    hasPath(/(?:check-boundaries|arch-fitness|architecture.*test|check-max-lines)/) ||
    hasVeristackGate;

  const hasPreCommitHook =
    hasPath(/(?:^|\/)(?:lefthook\.ya?ml|\.husky\/|\.pre-commit-config\.ya?ml|git-hooks\/pre-commit)/) ||
    /core\.hooksPath/.test(configAndCi);

  const hasCodeowners = hasPath(/(?:^|\/)codeowners$/);
  const hasReviewMd = hasPath(/(?:^|\/)review\.md$/);
  const hasAgentsMd = hasPath(/(?:^|\/)(?:agents|claude)\.md$/);

  const hasPbt =
    /\b(?:fast-check|hypothesis|FsCheck|proptest|quickcheck)\b/i.test(testImportAndManifest) ||
    /\b(?:fc\.property|fc\.assert|proptest!|@given\s*\(|\[Property\b)/m.test(codeTestText);

  const hasMbt =
    /\b(?:RuleBasedStateMachine|FsCheck\.Experimental|proptest_state_machine|ReferenceStateMachine|state_machine_test!|fc\.commands)\b/.test(
      codeTestText,
    ) || /\bstateright\b/i.test(testImportAndManifest);

  const hasContractTool =
    /\b(?:@pact-foundation|pactnet|schemathesis|openapi|asyncapi)\b/i.test(`${manifestAndConfig}\n${testImportLines}`) ||
    hasPath(/(?:^|\/)(?:buf\.yaml|openapi\.(?:ya?ml|json)|asyncapi\.(?:ya?ml|json)|.*\.contract\.[cm]?[jt]sx?)$/);

  const hasComponentUiTool =
    /@testing-library|playwright\/experimental-ct|\bstorybook\b/i.test(testImportAndManifest);

  const hasMsw = /\bmsw\b/i.test(testImportAndManifest) || /\b(?:setupServer|setupWorker)\s*\(/.test(codeTestText);
  const hasMswStrict = /onUnhandledRequest\s*:\s*["']error["']/.test(`${configText}\n${rawTestText}`);

  const hasTestcontainersOrRealDb =
    /\b(?:testcontainers|@testcontainers|pglite)\b/i.test(testImportAndManifest) ||
    /\b(?:UseNpgsql|UseSqlServer|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|firebase-emulator|Testcontainers)\b/.test(
      `${configAndCi}\n${codeTestText}`,
    );

  const hasMigrationTest =
    /\b(?:MigrateAsync|MigrationBuilder|alembic|flyway|prisma\s+migrate)\b/i.test(`${configAndCi}\n${codeTestText}`);

  const hasBusDlqTest =
    /\b(?:DeadLetter|MaxDeliveryCount|ServiceBusClient|RabbitMQ|Kafka)\b/.test(`${manifestText}\n${codeTestText}`);

  const hasDst =
    /\b(?:turmoil|antithesis)\b/i.test(testImportAndManifest) ||
    /\b(?:deterministicSimulation|virtualClock)\b/.test(codeTestText);

  const hasDryRun = /--dry-run|terraform\s+plan|ansible[^\n]*--check/i.test(configAndCi);

  const hasMutationTool =
    hasPath(/(?:^|\/)(?:mutants\.toml|stryker-config\.json|stryker\.conf\.[cm]?[jt]s)$/) ||
    /\b(?:@stryker-mutator|stryker|mutmut|cargo-mutants|pitest)\b/i.test(configAndCi) ||
    /\b(?:vstack(?:\.mjs)?|cli\.ts)\s+bench\b/i.test(effectiveCiText);

  const hasFormalTool =
    hasPath(/\.(?:tla|qnt|als|dfy|lean|bend)$|formal_model_check/) ||
    /\b(?:everystate|z3-solver|Microsoft\.Z3|stateright|kani|verus|loom|shuttle|quint|dafny|crosshair)\b/i.test(
      `${manifestText}\n${testImportLines}\n${effectiveCiText}`,
    ) ||
    (hasPath(/(?:^|\/)\.verification\/control-plan\.json$/) && hasPath(/(?:^|\/)\.verification\/laws\/.+\.laws\.json$/));

  const hasFuzzTool =
    /\b(?:cargo-fuzz|libFuzzer|jazzer|atheris)\b/i.test(`${manifestAndConfig}\n${effectiveCiText}`) ||
    /\bfuzzTest\s*\(/.test(codeTestText);

  const hasBombadil = /\bbombadil\b/i.test(configAndCi);

  const hasVisualTool =
    /\b(?:chromatic|percy|argos|@argos-ci)\b/i.test(configAndCi) ||
    /\btoHaveScreenshot\s*\(/.test(codeTestText);

  const hasPerfOrLoadTool =
    hasPath(/(?:^|\/)(?:check-perf-budget\.[cm]?[jt]s|k6\.config\.[cm]?[jt]s|lighthouserc\.(?:json|ya?ml|[cm]?js))$/) ||
    /\b(?:k6|BenchmarkDotNet|criterion|pytest-benchmark|web-vitals|lighthouse|@lhci\/cli)\b/i.test(
      `${manifestAndConfig}\n${effectiveCiText}\n${testImportLines}`,
    ) ||
    /\b(?:check-perf-budget|perf:check|(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:big-o|spc))\b/i.test(configAndCi);

  const hasE2eTool =
    /@playwright\/test|\b(?:playwright|cypress|selenium|puppeteer)\b/i.test(testImportAndManifest) ||
    hasPath(/(?:^|\/)(?:playwright\.config\.[cm]?[jt]s|cypress\.config\.[cm]?[jt]s|maestro\/)/);

  const hasProdTelemetryOrCanary =
    /\b(?:@opentelemetry|opentelemetry|launchdarkly|dd-trace|@sentry|sentry-sdk|prometheus|goreplay|chaos-mesh)\b/i.test(
      `${manifestText}\n${prodImportLines}\n${effectiveCiText}`,
    ) || /\b(?:canary|synthetic|rollback|post-deploy)\b/i.test(effectiveCiText);

  const hasDiffSelection =
    /\b(?:testscope|--changed|--affected|affected-projects|turbo\s+run[^\n]*--filter)\b/i.test(configAndCi);

  const runsUnitTests =
    hasCiWorkflows &&
    /\b(?:bun\s+test|vitest|jest|node\s+--test|mocha|ava|dotnet\s+test|cargo\s+test|pytest|go\s+test|phpunit|rspec)\b/i.test(
      effectiveCiText,
    );

  const ci: CiExecutionSignals = {
    hasCiWorkflows,
    workflowFiles,
    runsFormatterOrLint:
      hasCiWorkflows &&
      /\b(?:oxlint|oxfmt|eslint|prettier|biome|ruff\s+(?:check|format)|cargo\s+(?:fmt|clippy)|dotnet\s+(?:format|build\b[^\n]*warnaserror)|gofmt|golangci-lint|go\s+vet|(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:scan|no-comments|state-machines))\b/i.test(
        effectiveCiText,
      ),
    runsTypeOrStructureCheck:
      hasCiWorkflows &&
      /\b(?:tsc\b|tsgo\b|bun\s+(?:run\s+)?build|dotnet\s+build|cargo\s+(?:check|clippy|build)|mypy\b|pyright\b|go\s+(?:vet|build)|knip\b|deslop-please|check-max-lines|(?:vstack(?:\.mjs)?|cli\.ts)\s+scan)\b/i.test(
        effectiveCiText,
      ),
    runsUnitTests,
    runsBoundaryOrMbtTests:
      hasCiWorkflows &&
      (runsUnitTests || /\b(?:pact|storybook|test:contract|test:component|test:mbt)\b/i.test(effectiveCiText)),
    runsIntegrationOrDbTests:
      hasCiWorkflows &&
      /\b(?:testcontainers|integration|postgres|firestore|emulator|migrate|prisma\s+migrate|alembic|flyway|test:int|docker\s+compose)\b/i.test(
        effectiveCiText,
      ),
    runsMutationOrFormal:
      hasCiWorkflows &&
      (/\b(?:stryker|mutmut|cargo-mutants|pitest|quint|tlc|dafny|kani|formal-sync|chromatic|percy|argos|bombadil)\b/i.test(
        effectiveCiText,
      ) ||
        /\bbend\b[^\n]*--check-only/i.test(effectiveCiText) ||
        /\b(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:laws|bench|formal-sync)\b/i.test(effectiveCiText)),
    runsPerfOrBench:
      hasCiWorkflows &&
      /\b(?:k6\b|BenchmarkDotNet|cargo\s+bench|pytest-benchmark|lighthouse|lhci|check-perf-budget|perf:check|(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:big-o|spc)|load-test)\b/i.test(
        effectiveCiText,
      ),
    runsE2eTests:
      hasCiWorkflows && /\b(?:playwright|cypress|maestro|test:e2e|e2e)\b/i.test(effectiveCiText),
    runsProdVerification:
      hasCiWorkflows &&
      /\b(?:synthetic|canary|rollback|smoke-prod|post-deploy|healthcheck)\b/i.test(effectiveCiText),
  };

  const signals: ToolSignals = {
    hasFormatter,
    hasLinter,
    hasOxlint,
    hasAntiSlop,
    hasLandmines,
    hasGoInternal,
    hasDeslopPlease,
    hasDesloppify,
    hasStrictTypes,
    hasTsgo,
    hasKnipOrDeadCode,
    hasJscpd,
    hasArchFitness,
    hasPreCommitHook,
    hasCodeowners,
    hasReviewMd,
    hasAgentsMd,
    hasPbt,
    hasMbt,
    hasContractTool,
    hasComponentUiTool,
    hasMsw,
    hasMswStrict,
    hasTestcontainersOrRealDb,
    hasMigrationTest,
    hasBusDlqTest,
    hasDst,
    hasDryRun,
    hasMutationTool,
    hasFormalTool,
    hasFuzzTool,
    hasBombadil,
    hasVisualTool,
    hasPerfOrLoadTool,
    hasE2eTool,
    hasProdTelemetryOrCanary,
    hasDiffSelection,
  };

  return { signals, ci };
}
