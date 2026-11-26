import path from "node:path";
import type { ScannedFile } from "../discover.ts";
import type { CiExecutionSignals, Language, ToolSignals } from "../types.ts";
import { sanitizeShellBlock } from "./command-audit.ts";
import { isHostRepoFile } from "./manifest.ts";
import { auditCodeownersPerimeter, parseGitHubWorkflow } from "./workflow-audit.ts";

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
  if (lower === ".verification/rungs.json") return false;
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

function parsePackageScriptsByDir(files: readonly ScannedFile[]): Map<string, Map<string, string>> {
  const byDir = new Map<string, Map<string, string>>();
  for (const file of files) {
    if (!isHostRepoFile(file.rel)) continue;
    if (path.posix.basename(file.rel).toLowerCase() !== "package.json") continue;
    const rawDir = path.posix.dirname(file.rel);
    const dir = rawDir === "." ? "" : rawDir;
    try {
      const parsed = JSON.parse(file.content) as { scripts?: Record<string, unknown> };
      const map = byDir.get(dir) ?? new Map<string, string>();
      if (parsed.scripts && typeof parsed.scripts === "object") {
        for (const [name, cmd] of Object.entries(parsed.scripts)) {
          if (typeof cmd === "string" && cmd.trim().length > 0 && !map.has(name)) map.set(name, cmd);
        }
      }
      byDir.set(dir, map);
    } catch {
      byDir.set(dir, byDir.get(dir) ?? new Map<string, string>());
    }
  }
  return byDir;
}

function collectReferencedScriptNames(text: string): Array<{ name: string; recursive: boolean }> {
  const names: Array<{ name: string; recursive: boolean }> = [];
  const runRe = /\b(?:npm|pnpm|yarn|bun|turbo)\s+(?:(-r|--recursive)\s+)?(?:run\s+)?([a-zA-Z0-9:_-]+)/g;
  for (const match of text.matchAll(runRe)) {
    const candidate = match[2];
    if (candidate && candidate !== "install" && candidate !== "ci" && candidate !== "exec" && candidate !== "dlx" && candidate !== "x") {
      names.push({ name: candidate, recursive: Boolean(match[1]) });
    }
  }
  return names;
}

function buildActivePrCiText(files: readonly ScannedFile[]): {
  hasCiWorkflows: boolean;
  workflowFiles: string[];
  effectiveCiText: string;
  scheduledOrDeployText: string;
} {
  const workflows = files.filter((f) => f.isWorkflow);
  if (workflows.length === 0) return { hasCiWorkflows: false, workflowFiles: [], effectiveCiText: "", scheduledOrDeployText: "" };
  const activeWorkflowFiles: string[] = [];
  const chunks: string[] = [];
  const scheduledChunks: string[] = [];
  const scopedChunks: Array<{ cwd: string; text: string }> = [];

  const parsedGha = workflows
    .filter((wf) => wf.rel.startsWith(".github/workflows/"))
    .map((wf) => ({ wf, info: parseGitHubWorkflow(wf, files) }));
  const matchedPathPool = new Set<string>();
  for (const { info } of parsedGha) {
    if (info.hasPrOrPushTrigger && info.activeCommands.length > 0 && info.matchedPaths) {
      for (const mp of info.matchedPaths) matchedPathPool.add(mp);
    }
  }
  const partitionedSiblingCovered = (ignored: readonly string[] | undefined): boolean =>
    Boolean(ignored && ignored.length > 0 && ignored.every((p) => matchedPathPool.has(p)));

  for (const { wf, info } of parsedGha) {
    const isSchedOrDeploy = info.triggers.some((t) => t === "schedule" || t === "workflow_run" || t === "deployment_status");
    if (isSchedOrDeploy) {
      if (info.activeCommands.length > 0) scheduledChunks.push(...info.activeCommands);
      if (/(?:canary|drift|synthetic|smoke|rollback|post-deploy|mutation|bombadil)/i.test(wf.rel) && !wf.content.includes("if: false")) {
        scheduledChunks.push(wf.rel);
      }
    }
    if (info.deployCommands && info.deployCommands.length > 0) scheduledChunks.push(...info.deployCommands);
    const isPartitionedMain = !info.isPrBlocking && Boolean(info.hasPrOrPushTrigger) && partitionedSiblingCovered(info.ignoredPaths);
    const isPartitionedSibling = !info.isPrBlocking && Boolean(info.hasPrOrPushTrigger) && Boolean(info.matchedPaths?.some((mp) => parsedGha.some((o) => o.info.ignoredPaths?.includes(mp))));
    if ((!info.isPrBlocking && !isPartitionedMain && !isPartitionedSibling) || info.activeCommands.length === 0) continue;
    activeWorkflowFiles.push(wf.rel);
    chunks.push(...info.activeCommands);
    for (const sc of info.scopedCommands ?? info.activeCommands.map((c) => ({ cwd: "", command: c }))) scopedChunks.push({ cwd: sc.cwd, text: sc.command });
  }
  for (const wf of workflows) {
    if (wf.rel.startsWith(".github/workflows/")) continue;
    const lines = sanitizeShellBlock(wf.content);
    if (lines.length > 0) {
      activeWorkflowFiles.push(wf.rel);
      chunks.push(...lines);
      for (const l of lines) scopedChunks.push({ cwd: "", text: l });
    }
  }
  const scheduledOrDeployText = scheduledChunks.join("\n");
  if (chunks.length === 0) return { hasCiWorkflows: false, workflowFiles: [], effectiveCiText: "", scheduledOrDeployText };

  const pkgByDir = parsePackageScriptsByDir(files);
  const fileByRel = new Map(files.map((f) => [f.rel.replace(/\\/g, "/"), f]));
  const visitedScripts = new Set<string>();
  const visitedShells = new Set<string>();
  let frontier = scopedChunks;
  for (let depth = 0; depth < 4; depth++) {
    const nextFrontier: Array<{ cwd: string; text: string }> = [];
    for (const item of frontier) {
      for (const sm of item.text.matchAll(/(?:^|[\s&|;(])(?:(?:ba)?sh\s+)?(?:\.\/)?([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\.sh)\b/g)) {
        const rawPath = sm[1] ?? "";
        if (!rawPath || rawPath.includes("..")) continue;
        const resolved = item.cwd ? `${item.cwd}/${rawPath}` : rawPath;
        const shFile = fileByRel.get(resolved) ?? fileByRel.get(rawPath);
        if (!shFile || visitedShells.has(shFile.rel)) continue;
        visitedShells.add(shFile.rel);
        const shLines = sanitizeShellBlock(shFile.content);
        if (shLines.length > 0) { const joined = shLines.join("\n"); chunks.push(joined); nextFrontier.push({ cwd: item.cwd, text: joined }); }
      }
      for (const { name, recursive } of collectReferencedScriptNames(item.text)) {
        const dirs = recursive ? [...pkgByDir.keys()] : [pkgByDir.has(item.cwd) ? item.cwd : ""];
        for (const d of dirs) {
          const dirScripts = pkgByDir.get(d);
          const key = `${d}::${name}`;
          if (!dirScripts || visitedScripts.has(key)) continue;
          visitedScripts.add(key);
          const rawBody = dirScripts.get(name);
          if (!rawBody) continue;
          const bodyLines = sanitizeShellBlock(rawBody);
          if (bodyLines.length > 0) { const joined = bodyLines.join("\n"); chunks.push(joined); nextFrontier.push({ cwd: d, text: joined }); }
        }
      }
    }
    if (nextFrontier.length === 0) break;
    frontier = nextFrontier;
  }
  return { hasCiWorkflows: true, workflowFiles: activeWorkflowFiles.sort(), effectiveCiText: chunks.join("\n"), scheduledOrDeployText };
}

function hasNonEmptyLefthook(files: readonly ScannedFile[]): boolean {
  const lh = files.find((f) => path.posix.basename(f.rel).toLowerCase() === "lefthook.yml");
  if (!lh) return false;
  const cleaned = lh.content
    .split(/\r?\n/)
    .map((l) => l.replace(/^\s*#.*$/, ""))
    .join("\n");
  return /\bpre-commit\s*:/.test(cleaned) && /\brun\s*:\s*\S+/.test(cleaned);
}

function hasValidStrykerConfig(files: readonly ScannedFile[]): boolean {
  const cfg = files.find((f) => /(?:^|\/)stryker-config\.json$/i.test(f.rel));
  if (!cfg) return false;
  try {
    const parsed = JSON.parse(cfg.content) as Record<string, unknown>;
    if (typeof parsed !== "object" || parsed === null) return false;
    return (
      "mutate" in parsed ||
      "testRunner" in parsed ||
      "checkers" in parsed ||
      "stryker-config" in parsed ||
      "thresholds" in parsed
    );
  } catch {
    return false;
  }
}

function hasNonEmptyFormalSpec(files: readonly ScannedFile[]): boolean {
  for (const f of files) {
    if (!/\.(?:tla|qnt|als|dfy|lean|bend)$/.test(f.rel)) continue;
    const body = f.content
      .split(/\r?\n/)
      .map((l) => l.replace(/^\s*(?:--|\/\/|#).*$/, "").trim())
      .filter(Boolean)
      .join("\n");
    if (
      body.length >= 20 &&
      /\b(?:module|theorem|law|def|action|val|invariant|lemma|method|predicate|sig|fact|MODULE)\b/.test(body)
    ) {
      return true;
    }
  }
  return false;
}

function hasStrictTypesForLanguages(
  languages: readonly Language[],
  configText: string,
  manifestAndConfig: string,
  effectiveCiText: string,
  hostFiles: readonly ScannedFile[],
): boolean {
  const needsTs = languages.includes("typescript"); const needsCs = languages.includes("csharp");
  const needsPy = languages.includes("python"); const needsRust = languages.includes("rust"); const needsGo = languages.includes("go");
  if (needsTs) {
    const tsconfigs = hostFiles.filter((f) => /^tsconfig(?:\.[^/]+)?\.json$/i.test(path.posix.basename(f.rel)));
    if (tsconfigs.length === 0 || !tsconfigs.some((f) => /"strict"\s*:\s*true/.test(f.content))) return false;
    if (tsconfigs.some((f) => /"(?:strict|strictNullChecks|noImplicitAny)"\s*:\s*false/.test(f.content))) return false;
  }
  if (needsCs) {
    const csFiles = hostFiles.filter((f) => /\.(?:csproj|props)$/i.test(f.rel));
    if (!/<Nullable>enable<\/Nullable>/i.test(manifestAndConfig)) return false;
    if (csFiles.some((f) => /<Nullable>\s*disable\s*<\/Nullable>|<TreatWarningsAsErrors>\s*false\s*<\/TreatWarningsAsErrors>/i.test(f.content))) {
      return false;
    }
  }
  if (needsPy) {
    const pyText = `${configText}\n${effectiveCiText}`;
    if (/"typeCheckingMode"\s*:\s*"off"/i.test(configText)) return false;
    const hasMypyStrict =
      /\[tool\.mypy\][\s\S]{0,400}\bstrict\s*=\s*true\b/i.test(configText) ||
      /\[mypy\][\s\S]{0,400}\bstrict\s*=\s*true\b/i.test(configText) ||
      /\bmypy\b[^\n]*--strict/i.test(pyText) ||
      /"typeCheckingMode"\s*:\s*"strict"/i.test(configText) ||
      /\bbasedpyright\b/i.test(pyText);
    if (!hasMypyStrict) return false;
  }
  if (needsRust) {
    const rustText = `${manifestAndConfig}\n${effectiveCiText}`;
    const hasRustStrict =
      /unsafe_code\s*=\s*"(?:forbid|deny)"|clippy::[a-z_]+\s*=\s*"deny"|warnings\s*=\s*"deny"|--\s*-D\s+warnings|\bcargo\s+(?:check|build|clippy|test|nextest)\b/i.test(
        rustText,
      );
    if (!hasRustStrict) return false;
  }
  if (needsGo && !/\b(?:go\s+vet|golangci-lint)\b/i.test(`${configText}\n${effectiveCiText}`)) {
    return false;
  }
  return needsTs || needsCs || needsPy || needsRust || needsGo;
}

export function extractSignals(
  files: readonly ScannedFile[],
  allRelPaths: readonly string[],
  languages: readonly Language[],
): { signals: ToolSignals; ci: CiExecutionSignals } {
  const hostFiles = files.filter((f) => isHostRepoFile(f.rel));
  const hostPaths = allRelPaths.filter((p) => isHostRepoFile(p)).map((p) => p.toLowerCase());
  const allLowerPaths = allRelPaths.map((p) => p.toLowerCase());
  const hasHostPath = (re: RegExp): boolean => hostPaths.some((p) => re.test(p));
  const hasAnyPath = (re: RegExp): boolean => allLowerPaths.some((p) => re.test(p));

  const manifestText = hostFiles
    .filter((f) => isManifestFile(f.rel))
    .map((f) => f.content)
    .join("\n");

  const configText = hostFiles
    .filter((f) => isConfigFile(f) && !f.isWorkflow)
    .map((f) => f.content)
    .join("\n");

  const hostTestFiles = hostFiles.filter((f) => f.isTest);
  const rawTestText = hostTestFiles.map((f) => f.content).join("\n");
  const codeTestText = hostTestFiles.map((f) => stripCodeStringsAndComments(f.content)).join("\n");

  const testImportLines = hostTestFiles
    .flatMap((f) => f.content.split(/\r?\n/))
    .filter((line) => /^\s*(?:import|from|use|using|require\s*\(|const\s+\w+\s*=\s*require\()/.test(line))
    .join("\n");

  const prodImportLines = hostFiles
    .filter((f) => f.language && !f.isTest && !f.rel.startsWith("src/rungs/"))
    .flatMap((f) => f.content.split(/\r?\n/))
    .filter((line) => /^\s*(?:import|from|use|using)\b/.test(line))
    .join("\n");

  const { hasCiWorkflows, workflowFiles, effectiveCiText, scheduledOrDeployText } = buildActivePrCiText(files);
  const configAndCi = `${configText}\n${effectiveCiText}`;
  const manifestAndConfig = `${manifestText}\n${configText}`;
  const testImportAndManifest = `${manifestText}\n${testImportLines}`;
  const codeownersAudit = auditCodeownersPerimeter(hostFiles, allRelPaths);

  const hasFormatter =
    hasHostPath(/(?:^|\/)(?:\.?prettier|oxfmt|\.editorconfig|rustfmt\.toml|\.rustfmt\.toml|biome\.jsonc?|ruff\.toml|\.ruff\.toml)/) ||
    /\[tool\.ruff(?:\.format)?\]|\b(?:prettier|oxfmt|biome|ruff\s+format|dotnet\s+format|gofmt|goimports|rustfmt|cargo\s+fmt)\b/i.test(configAndCi);

  const hasOxlint = hasHostPath(/(?:^|\/)(?:\.oxlintrc\.jsonc?|oxlint\.config\.[cm]?[jt]s)$/) || /\boxlint\b/i.test(configAndCi);

  const hasLinter =
    hasOxlint ||
    hasHostPath(/(?:^|\/)(?:\.?eslint|biome\.jsonc?|ruff\.toml|\.ruff\.toml|clippy\.toml|\.clippy\.toml|\.golangci\.ya?ml|directory\.build\.props)/) ||
    /\[tool\.ruff(?:\.lint)?\]|\b(?:eslint|oxlint|biome|ruff\s+check|clippy|golangci-lint|staticcheck|roslyn|AnalysisLevel|VStack\.Analyzers)\b/i.test(configAndCi);

  const hasAntiSlop =
    /\b(?:anti-slop|dmmulroy\/anti-slop|VStack\.Analyzers)\b/i.test(configText) ||
    /\b(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:scan|verify|no-comments|state-machines)\b/i.test(effectiveCiText);

  const hasLandmines =
    /@interfere\/landmines|landmines-testing|\blandmines\//i.test(configText) ||
    /\b(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:scan|verify)\b/i.test(effectiveCiText);

  const hasGoInternal = /\boxlint-plugin-go-internal\b/i.test(configText);
  const hasDeslopPlease = hasHostPath(/\.deslop-please\.allow/) || /\bdeslop-please\b/i.test(configAndCi);
  const hasDesloppify = /\bdesloppify\b/i.test(configAndCi);

  const hasStrictTypes = hasStrictTypesForLanguages(languages, configText, manifestAndConfig, effectiveCiText, hostFiles);
  const hasTsgo = /\btsgo\b|@typescript\/native-preview/i.test(configAndCi);

  const hasKnipOrDeadCode =
    hasHostPath(/(?:^|\/)knip\.jsonc?$/) ||
    /\b(?:knip|vulture|deadcode|cargo-udeps|cargo-machete)\b|"noUnusedLocals"\s*:\s*true|CS0162|IDE0051|dead_code|<AnalysisLevel>latest|\bclippy\b|\bruff\s+check\b|\bgo\s+vet\b/i.test(
      `${manifestAndConfig}\n${effectiveCiText}`,
    );

  const hasJscpd = hasHostPath(/jscpd/) || /\bjscpd\b/i.test(configAndCi);

  const hasArchFitness =
    /\b(?:dependency-cruiser|archunit|netarchtest|import-linter|deptrac|packwerk|turbo\s+boundaries|check-max-lines)\b/i.test(
      `${configAndCi}\n${testImportLines}`,
    ) ||
    hasHostPath(/(?:check-boundaries|arch-fitness|architecture.*test|clippy\.toml|\.golangci\.ya?ml|(?:^|\/)internal\/.+\.go$)/);

  const hasPreCommitHook =
    hasNonEmptyLefthook(hostFiles) ||
    hasHostPath(/(?:^|\/)(?:\.husky\/pre-commit|\.pre-commit-config\.ya?ml|git-hooks\/pre-commit)/) ||
    /core\.hooksPath/.test(configText);

  const hasCodeowners = codeownersAudit.passed;
  const hasReviewMd = hasHostPath(/(?:^|\/)review\.md$/);
  const hasAgentsMd = hasHostPath(/(?:^|\/)(?:agents|claude)\.md$/);

  const hasPbt =
    /(?:\bfc\.property\s*\(|\bfc\.asyncProperty\s*\(|\bproptest!\s*\{|@(?:hypothesis\.)?given\s*\(|\[Property\b|\brapid\.Check\s*\(|\bquick\.Check\s*\()/m.test(
      codeTestText,
    );

  const hasNonEmptyFcCommands = /\bfc\.commands\s*\(\s*\[(?!\s*\])/.test(codeTestText);
  const hasMbt =
    hasNonEmptyFcCommands ||
    /\b(?:RuleBasedStateMachine|FsCheck\.Experimental|proptest_state_machine|ReferenceStateMachine|state_machine_test!|rapid\.StateMachine)\b/.test(
      codeTestText,
    ) ||
    /\bstateright\b/i.test(testImportLines);

  const hasContractTool =
    /@pact-foundation|\b(?:pactnet|pact-go|schemathesis|openapi|asyncapi)\b/i.test(`${manifestAndConfig}\n${testImportLines}`) ||
    hasHostPath(/(?:^|\/)(?:buf\.yaml|openapi\.(?:ya?ml|json)|asyncapi\.(?:ya?ml|json)|.*\.contract\.[cm]?[jt]sx?)$/);

  const hasComponentUiTool =
    /@testing-library|playwright\/experimental-ct|\bstorybook\b/i.test(testImportAndManifest);

  const hasMsw = /\bmsw\b/i.test(testImportAndManifest) || /\b(?:setupServer|setupWorker)\s*\(/.test(codeTestText);
  const hasMswStrict = /onUnhandledRequest\s*:\s*["']error["']/.test(`${configText}\n${rawTestText}`);

  const hasInProcessRealDb = /@electric-sql\/pglite|\bpglite\b/i.test(`${testImportAndManifest}\n${codeTestText}`);
  const hasTestcontainersOrRealDb =
    hasInProcessRealDb ||
    /@testcontainers|\btestcontainers\b/i.test(testImportAndManifest) ||
    /\b(?:UseNpgsql|UseSqlServer|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|firebase-emulator|Testcontainers)\b/.test(
      `${configAndCi}\n${codeTestText}`,
    );

  const hasMigrationTest =
    hasHostPath(/(?:^|\/)[^/]*migrat(?:e|ion)[^/]*\.(?:test|spec)\.[cm]?[jt]sx?$/i) ||
    /\b(?:MigrateAsync|MigrationBuilder|alembic|flyway|prisma\s+migrate|sqlx::migrate|golang-migrate|goose|drizzle-kit)\b/i.test(`${configAndCi}\n${codeTestText}`);

  const hasBusDlqTest = /\b(?:DeadLetter|MaxDeliveryCount|ServiceBusClient|RabbitMQ|Kafka)\b/.test(`${manifestText}\n${codeTestText}`);
  const hasDst = /\b(?:turmoil|antithesis)\b/i.test(testImportAndManifest) || /\b(?:deterministicSimulation|virtualClock)\b/.test(codeTestText);
  const hasDryRun = /--dry-run|terraform\s+plan|ansible[^\n]*--check/i.test(configAndCi);

  const hasMutationTool =
    hasValidStrykerConfig(hostFiles) ||
    hasHostPath(/(?:^|\/)(?:mutants\.toml|stryker\.conf(?:ig)?\.[cm]?[jt]s)$/) ||
    /@stryker-mutator|\b(?:stryker\s+run|dotnet\s+stryker|mutmut\s+run|cargo\s+mutants|pitest|gremlins|go-mutesting|(?:vstack(?:\.mjs)?|cli\.ts)\s+canary)\b/i.test(configAndCi);

  const hasFormalTool =
    hasNonEmptyFormalSpec(files) ||
    hasHostPath(/(?:^|\/)test_formal_model_check\.py$/) ||
    /\b(?:everystate|z3-solver|Microsoft\.Z3|stateright|kani|verus|loom|shuttle|quint\s+(?:verify|run)|dafny\s+verify|crosshair)\b/i.test(`${testImportLines}\n${effectiveCiText}`) ||
    (hasAnyPath(/(?:^|\/)\.verification\/control-plan\.json$/) && hasAnyPath(/(?:^|\/)\.verification\/laws\/.+\.laws\.json$/));

  const hasFuzzTool =
    /\b(?:cargo-fuzz|libFuzzer|jazzer|atheris|SharpFuzz|go\s+test[^\n]*-fuzz)\b/i.test(`${manifestAndConfig}\n${effectiveCiText}`) ||
    /\bfuzzTest\s*\(|\bfunc\s+Fuzz[A-Z]\w*\s*\(/.test(codeTestText);

  const hasBombadil = /\bbombadil\b/i.test(`${configAndCi}\n${scheduledOrDeployText}`) || hasHostPath(/(?:^|\/)tests\/bombadil\//);
  const hasVisualTool = /@argos-ci|\b(?:chromatic|percy|argos)\b/i.test(configAndCi) || /\btoHaveScreenshot\s*\(/.test(codeTestText);

  const hasPerfOrLoadTool =
    hasHostPath(/(?:^|\/)(?:check-perf-budget\.[cm]?[jt]s|k6\.config\.[cm]?[jt]s|lighthouserc\.(?:json|ya?ml|[cm]?js)|(?:tests\/load|k6)\/[^/]+\.(?:[cm]?[jt]s|py|go))$/) ||
    /@lhci\/cli|\b(?:k6\s+run|BenchmarkDotNet|NBomber|criterion|cargo\s+bench|cargo\s+(?:\+\w+\s+)?test[^\n]*--benches|codspeed|divan|locust|tinybench|mitata|pytest-benchmark|pytest[^\n]*--benchmark|go\s+test[^\n]*-bench|web-vitals|lighthouse|check-perf-budget|(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:big-o|spc))\b/i.test(`${manifestAndConfig}\n${effectiveCiText}\n${testImportLines}`);

  const hasE2eTool =
    /@playwright\/test|\b(?:playwright|cypress|selenium|puppeteer)\b/i.test(testImportAndManifest) ||
    hasHostPath(/(?:^|\/)(?:playwright\.config\.[cm]?[jt]s|cypress\.config\.[cm]?[jt]s|maestro\/)/);

  const hasProdTelemetryOrCanary =
    hasHostPath(/(?:^|\/)(?:scripts\/canary\/|production-canar|production-drift|derived-device-drift|synthetic[-_]check|smoke[-_]prod)/) ||
    /@opentelemetry|@sentry|\b(?:opentelemetry|launchdarkly|dd-trace|sentry-sdk|prometheus|goreplay|chaos-mesh)\b/i.test(`${manifestText}\n${prodImportLines}\n${effectiveCiText}`) ||
    /\b(?:canary|production-drift|synthetic|rollback|post-deploy|smoke[-_]|Smoke check production)\b/i.test(`${effectiveCiText}\n${scheduledOrDeployText}`);

  const hasDiffSelection =
    /\b(?:testscope|--changed|--affected|affected-projects|turbo\s+run[^\n]*--filter)\b/i.test(configAndCi);

  const runsVerifyAll =
    hasCiWorkflows && /\b(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:verify|run-rung\s+all)\b/i.test(effectiveCiText);

  const runsUnitTests =
    runsVerifyAll ||
    (hasCiWorkflows &&
      /\b(?:bun\s+test|vitest|jest|node\s+--test|vp\s+test|deno\s+test|mocha|ava|dotnet\s+test|cargo\s+(?:test|nextest)|pytest|go\s+test|phpunit|rspec|bats\b|test\/ci-vm|test\/all|test:unit|test:coverage|pr-affected-vitest|run-rung\s+(?:R2|all))\b/i.test(
        effectiveCiText,
      ));

  const ci: CiExecutionSignals = {
    hasCiWorkflows,
    workflowFiles,
    runsFormatterOrLint:
      runsVerifyAll ||
      (hasCiWorkflows &&
        /\b(?:oxlint|oxfmt|eslint|prettier|biome|vp\s+(?:check|lint|fmt)|lint-ratchet|pr-lint-format|ruff\s+(?:check|format)|cargo\s+(?:fmt|clippy)|dotnet\s+(?:format|build\b[^\n]*warnaserror)|gofmt|golangci-lint|govulncheck|go\s+vet|(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:scan|no-comments|state-machines|run-rung))\b/i.test(
          effectiveCiText,
        )),
    runsTypeOrStructureCheck:
      runsVerifyAll ||
      (hasCiWorkflows &&
        /\b(?:tsc\b|tsgo\b|vp\s+check|typecheck|type-ratchet|dotnet\s+build|cargo\s+(?:check|clippy|build)|mypy\b|pyright\b|basedpyright\b|go\s+(?:vet|build)|golangci-lint|knip\b|vulture\b|deadcode\b|deslop-please|check-max-lines|(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:scan|run-rung))\b/i.test(
          effectiveCiText,
        )),
    runsUnitTests,
    runsBoundaryOrMbtTests:
      runsVerifyAll ||
      (hasCiWorkflows &&
        /\b(?:pact|pact-go|schemathesis|oasdiff|storybook|test:contract|test:component|test:mbt|mobile-contracts|bun\s+test|vitest|jest|node\s+--test|vp\s+test|deno\s+test|dotnet\s+test|pytest\b|cargo\s+(?:test|nextest)|go\s+test|run-rung\s+(?:R3|all))\b/i.test(
          effectiveCiText,
        )),
    runsIntegrationOrDbTests:
      runsVerifyAll ||
      (hasCiWorkflows &&
        ((hasInProcessRealDb && runsUnitTests) ||
          /\b(?:testcontainers|test:int|test:integration|cloud-integration|conformance|pytest[^\n]*-m\s+["']?integration|dotnet\s+test[^\n]*--filter[^\n]*Integration|cargo\s+(?:test|nextest)[^\n]*--test\s+integration|go\s+test[^\n]*-tags=integration|firebase\s+emulators:exec|prisma\s+migrate|alembic\s+upgrade|flyway\s+migrate|goose\s+up|run-rung\s+(?:R4|all))\b/i.test(
            effectiveCiText,
          ))),
    runsMutationOrFormal:
      runsVerifyAll ||
      (/\b(?:stryker\s+run|dotnet\s+stryker|mutmut\s+run|cargo\s+mutants|pitest|gremlins|go-mutesting|go\s+test[^\n]*-fuzz|crosshair|quint\s+(?:verify|run)|dafny\s+verify|kani\b|stateright|loom\b|z3\b|formal-sync|chromatic|percy|argos|bombadil|mutation(?:tests)?|run-rung\s+(?:R5|all))\b/i.test(`${effectiveCiText}\n${scheduledOrDeployText}`) ||
        (hasCiWorkflows && (/\bbend\b[^\n]*--check-only/i.test(effectiveCiText) || /\b(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:laws|canary|formal-sync)\b/i.test(effectiveCiText)))),
    runsPerfOrBench:
      runsVerifyAll ||
      (hasCiWorkflows &&
        /\b(?:k6\s+run|BenchmarkDotNet|NBomber|cargo\s+bench|cargo\s+(?:\+\w+\s+)?test[^\n]*--benches|codspeed|divan|locust|tinybench|mitata|pytest-benchmark|pytest[^\n]*--benchmark|go\s+test[^\n]*-bench|lighthouse|lhci|check-perf-budget|perf:check|(?:vstack(?:\.mjs)?|cli\.ts)\s+(?:big-o|spc)|run-rung\s+(?:R6|all))\b/i.test(effectiveCiText)),
    runsE2eTests:
      runsVerifyAll ||
      (hasCiWorkflows &&
        /\b(?:playwright\s+test|playwright-go|cypress\s+run|maestro\s+test|test:e2e|dashboard-e2e|pytest[^\n]*-m\s+["']?e2e|dotnet\s+test[^\n]*--filter[^\n]*E2E|cargo\s+(?:test|nextest)[^\n]*--test\s+e2e|go\s+test[^\n]*\/e2e|run-rung\s+(?:R7|all))\b/i.test(effectiveCiText)),
    runsProdVerification:
      runsVerifyAll ||
      /\b(?:synthetic|canary|production-canar|production-drift|rollback|smoke-prod|smoke-event-assets|post-deploy|healthcheck|run-rung\s+(?:R8|all))\b/i.test(`${effectiveCiText}\n${scheduledOrDeployText}`),
  };

  const signals: ToolSignals = {
    hasFormatter, hasLinter, hasOxlint, hasAntiSlop, hasLandmines, hasGoInternal,
    hasDeslopPlease, hasDesloppify, hasStrictTypes, hasTsgo, hasKnipOrDeadCode,
    hasJscpd, hasArchFitness, hasPreCommitHook, hasCodeowners, hasReviewMd,
    hasAgentsMd, hasPbt, hasMbt, hasContractTool, hasComponentUiTool, hasMsw,
    hasMswStrict, hasTestcontainersOrRealDb, hasMigrationTest, hasBusDlqTest,
    hasDst, hasDryRun, hasMutationTool, hasFormalTool, hasFuzzTool, hasBombadil,
    hasVisualTool, hasPerfOrLoadTool, hasE2eTool, hasProdTelemetryOrCanary, hasDiffSelection,
  };

  return { signals, ci };
}
