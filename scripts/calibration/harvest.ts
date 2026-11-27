import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export interface HarvestedManifest {
  path: string;
  kind: string;
  name?: string | null;
  private?: boolean;
  hasExports?: boolean;
  workspaces?: unknown;
  scripts?: Record<string, unknown>;
  dependencies?: string[];
  devDependencies?: string[];
  peerDependencies?: string[];
  snippet?: string;
  parseError?: boolean;
}

export interface RepoEvidencePacket {
  schemaVersion: 1;
  repoPath: string;
  repoName: string;
  commitSha: string;
  defaultBranch: string;
  totalTrackedFiles: number;
  languageCensus: Record<string, number>;
  topDirectoriesByLanguage: Array<{ dir: string; lang: string; files: number }>;
  symlinks: { total: number; docOrAgent: string[]; code: string[] };
  manifests: HarvestedManifest[];
  workflows: Array<{ path: string; lines: number; links: string[]; content: string }>;
  linkedCiArtifacts: Array<{ path: string; content: string }>;
  testSurface: {
    totalTestFiles: number;
    inlineRustTestFilesCount: number;
    inlineRustTestSample: string[];
    topTestDirectories: Array<[string, number]>;
    verificationSignals: Record<string, string[]>;
  };
}

const CODE_EXT_LANG = new Map<string, string>([
  [".ts", "typescript"], [".tsx", "typescript"], [".mts", "typescript"], [".cts", "typescript"],
  [".js", "javascript"], [".jsx", "javascript"], [".mjs", "javascript"], [".cjs", "javascript"],
  [".py", "python"], [".rs", "rust"], [".go", "go"], [".cs", "csharp"],
  [".sh", "shell"], [".bash", "shell"], [".ps1", "powershell"], [".sql", "sql"],
  [".vue", "vue"], [".svelte", "svelte"], [".astro", "astro"], [".nix", "nix"], [".qml", "qml"],
  [".tla", "formal"], [".qnt", "formal"], [".bend", "formal"], [".dfy", "formal"], [".lean", "formal"],
]);

const MANIFEST_BASES = new Set([
  "package.json", "pyproject.toml", "cargo.toml", "go.mod", "turbo.json",
  "makefile", "justfile", "taskfile.yml", "build.ps1", "build.cake", "cake.cs",
  "lefthook.yml", ".pre-commit-config.yaml", ".pre-commit-config.yml",
  "codeowners", "dockerfile", "stryker-config.json", "stryker-config.jsonc",
  "mutants.toml", "knip.json", "knip.jsonc", ".oxlintrc.json", ".oxlintrc.jsonc",
  "oxlint.config.ts", "biome.json", "biome.jsonc", ".golangci.yml", ".golangci.yaml",
  "ruff.toml", ".ruff.toml", "mypy.ini", "pyrightconfig.json", "directory.build.props",
]);

const TEST_PATH_RE =
  /(?:\.(?:test|spec|e2e|cy|int|integration|contract)\.[cm]?[jt]sx?$|_test\.go$|(?:^|[-_])tests?\.(?:py|rs|sh|bash)$|^test[-_].*\.py$|tests?\.cs$|specs?\.cs$|(?:^|\/)(?:tests?|__tests__|e2e|specs?)\/)/i;

const VERIFICATION_SIGNAL_RE: ReadonlyArray<readonly [string, RegExp]> = [
  ["pbt", /\b(?:fast-check|fc\.property|fc\.asyncProperty|hypothesis|@given|proptest!|FsCheck|rapid\.Check|quick\.Check)\b/],
  ["mbt", /\b(?:fc\.commands|RuleBasedStateMachine|proptest_state_machine|stateright|rapid\.StateMachine)\b/],
  ["mutation", /\b(?:stryker|mutmut|cargo-mutants|cargo\s+mutants|gremlins|pitest|MutationTests)\b/i],
  ["formal", /\b(?:tla|quint|dafny|kani|stateright|z3-solver|everystate|crosshair|cargo\s+(?:\+\w+\s+)?miri)\b/i],
  ["perf-bench", /\b(?:k6|codspeed|criterion|BenchmarkDotNet|pytest-benchmark|tinybench|mitata|lighthouse\s+(?:https?:|--)|@lhci\/cli|go\s+test[^\n]*-bench)\b/i],
  ["e2e", /\b(?:@playwright\/test|playwright|cypress|selenium|puppeteer|maestro)\b/i],
  ["real-db", /\b(?:testcontainers|pglite|UseNpgsql|FIRESTORE_EMULATOR_HOST|docker\s+compose|sqlx::test)\b/i],
  ["migrations", /\b(?:drizzle-kit|prisma\s+migrate|alembic|flyway|goose|golang-migrate|MigrateAsync|sqlx::migrate)\b/i],
  ["contracts", /\b(?:pact|schemathesis|openapi|asyncapi|oasdiff|buf\.yaml)\b/i],
  ["telemetry-canary", /\b(?:opentelemetry|@sentry|sentry-sdk|prometheus|datadog|dd-trace|launchdarkly|canary|synthetic|rollback)\b/i],
  ["custom-lint", /\b(?:ast-grep|oxlint|biome|ruff|golangci-lint|clippy|roslyn|shellcheck|zizmor|prek)\b/i],
];

function runGit(repoRoot: string, args: readonly string[]): string {
  const res = spawnSync("git", ["-C", repoRoot, ...args], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  return res.status === 0 ? (res.stdout ?? "") : "";
}

function readBounded(absPath: string, maxChars = 16_000): string {
  try {
    const stat = fs.lstatSync(absPath);
    if (!stat.isFile() || stat.size > 512_000) return "";
    const raw = fs.readFileSync(absPath, "utf8");
    return raw.length > maxChars ? `${raw.slice(0, maxChars)}\n...<truncated ${raw.length - maxChars} chars>` : raw;
  } catch {
    return "";
  }
}

function classifySymlinkTarget(rel: string): "doc-or-agent" | "code" | "other" {
  if (/^(?:CLAUDE|AGENTS|GEMINI|README)\.md$|^\.(?:claude|agents|cursor|codex)\/|^docs\//i.test(rel)) return "doc-or-agent";
  if (CODE_EXT_LANG.has(path.posix.extname(rel).toLowerCase())) return "code";
  return "other";
}

function listTrackedFiles(repoRoot: string): string[] {
  const raw = runGit(repoRoot, ["ls-files", "-z"]);
  if (raw) return raw.split("\0").filter(Boolean);
  const out: string[] = [];
  const stack: string[] = [repoRoot];
  while (stack.length > 0 && out.length < 20_000) {
    const cur = stack.pop();
    if (!cur) break;
    let entries: fs.Dirent[] = [];
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.name === ".git" || e.name === "node_modules" || e.name === "target" || e.name === "dist") continue;
      const abs = path.join(cur, e.name);
      const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
      if (e.isDirectory()) stack.push(abs);
      else out.push(rel);
    }
  }
  return out.sort();
}

function summarizeManifest(rel: string, content: string): HarvestedManifest {
  const base = path.posix.basename(rel).toLowerCase();
  if (base === "package.json") {
    try {
      const pkg = JSON.parse(content) as Record<string, unknown>;
      const toKeys = (v: unknown): string[] => (v && typeof v === "object" && !Array.isArray(v) ? Object.keys(v) : []);
      return {
        path: rel,
        kind: "package.json",
        name: typeof pkg.name === "string" ? pkg.name : null,
        private: Boolean(pkg.private),
        hasExports: Boolean(pkg.exports),
        workspaces: pkg.workspaces ?? null,
        scripts: pkg.scripts && typeof pkg.scripts === "object" && !Array.isArray(pkg.scripts) ? (pkg.scripts as Record<string, unknown>) : {},
        dependencies: toKeys(pkg.dependencies),
        devDependencies: toKeys(pkg.devDependencies).slice(0, 40),
        peerDependencies: toKeys(pkg.peerDependencies),
      };
    } catch {
      return { path: rel, kind: "package.json", parseError: true };
    }
  }
  return { path: rel, kind: base, snippet: content.slice(0, 4_000) };
}

function extractWorkflowLinks(wfContent: string, trackedSet: ReadonlySet<string>): string[] {
  const refs = new Set<string>();
  for (const m of wfContent.matchAll(/uses:\s*["']?(\.\/[^"'\s#]+)/g)) {
    const base = (m[1] ?? "").replace(/^\.\//, "").replace(/\/+$/, "");
    for (const cand of [`${base}/action.yml`, `${base}/action.yaml`, base]) {
      if (trackedSet.has(cand)) refs.add(cand);
    }
  }
  for (const m of wfContent.matchAll(/(?:^|[\s&|;(])(?:(?:ba)?sh\s+|pwsh\s+|dotnet\s+run\s+)?(?:\.\/)?([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*\.(?:sh|bash|ps1|cake)|cake\.cs)\b/g)) {
    const cand = (m[1] ?? "").replace(/^\.\//, "");
    if (trackedSet.has(cand)) refs.add(cand);
  }
  return [...refs];
}

function recordHarvestSignals(signalHits: Map<string, string[]>, rel: string, text: string): void {
  for (const [sig, re] of VERIFICATION_SIGNAL_RE) {
    if (re.test(text)) {
      const list = signalHits.get(sig) ?? [];
      if (list.length < 8) list.push(rel);
      signalHits.set(sig, list);
    }
  }
}

function scanTrackedRepoFiles(root: string, tracked: readonly string[], trackedSet: ReadonlySet<string>) {
  if (!root) throw new Error("root is required");
  const dirLangCounts = new Map<string, number>();
  const langCounts = new Map<string, number>();
  const symlinks: Array<{ path: string; kind: "doc-or-agent" | "code" | "other" }> = [];
  const manifests: HarvestedManifest[] = [];
  const workflows: Array<{ path: string; lines: number; links: string[]; content: string }> = [];
  const testFiles: string[] = [];
  const inlineRustTestFiles: string[] = [];
  const signalHits = new Map<string, string[]>();
  const linkedScriptSet = new Set<string>();
  for (const rel of tracked) {
    const abs = path.join(root, rel);
    let stat: fs.Stats;
    try { stat = fs.lstatSync(abs); } catch { continue; }
    if (stat.isSymbolicLink()) { symlinks.push({ path: rel, kind: classifySymlinkTarget(rel) }); continue; }
    if (!stat.isFile()) continue;
    const ext = path.posix.extname(rel).toLowerCase();
    const base = path.posix.basename(rel).toLowerCase();
    const lang = CODE_EXT_LANG.get(ext);
    if (lang) {
      langCounts.set(lang, (langCounts.get(lang) ?? 0) + 1);
      const dlKey = `${rel.split("/").slice(0, 2).join("/")}::${lang}`;
      dirLangCounts.set(dlKey, (dirLangCounts.get(dlKey) ?? 0) + 1);
    }
    const isWorkflow =
      (rel.startsWith(".github/workflows/") && /\.(?:ya?ml)$/i.test(rel)) ||
      rel === ".gitlab-ci.yml" ||
      rel === ".circleci/config.yml" ||
      rel === "azure-pipelines.yml";
    if (isWorkflow) {
      const content = readBounded(abs, 18_000);
      const links = extractWorkflowLinks(content, trackedSet);
      for (const l of links) linkedScriptSet.add(l);
      workflows.push({ path: rel, lines: content.split(/\r?\n/).length, links, content });
      recordHarvestSignals(signalHits, rel, content);
      continue;
    }
    const isManifest = MANIFEST_BASES.has(base) || base.endsWith(".csproj") || base.endsWith(".sln") || base.endsWith(".slnx");
    if (isManifest && manifests.length < 120) {
      const content = readBounded(abs, 8_000);
      manifests.push(summarizeManifest(rel, content));
      recordHarvestSignals(signalHits, rel, content);
    }
    if (TEST_PATH_RE.test(rel)) {
      testFiles.push(rel);
      if (testFiles.length <= 250 && lang) recordHarvestSignals(signalHits, rel, readBounded(abs, 6_000));
    } else if (ext === ".rs" && stat.size <= 256_000) {
      const text = readBounded(abs, 64_000);
      if (/#\[cfg\(test\)\]/.test(text) && /#\[(?:test|tokio::test|rstest)\]/.test(text)) inlineRustTestFiles.push(rel);
    }
  }
  return { dirLangCounts, langCounts, symlinks, manifests, workflows, testFiles, inlineRustTestFiles, signalHits, linkedScriptSet };
}

export function harvestRepoEvidence(repoPath: string): RepoEvidencePacket {
  if (!repoPath) throw new Error("repoPath is required");
  const root = path.resolve(repoPath);
  const commitSha = runGit(root, ["rev-parse", "HEAD"]).trim() || "untracked";
  const originHead = runGit(root, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]).trim().replace(/^origin\//, "");
  const currentBranch = runGit(root, ["rev-parse", "--abbrev-ref", "HEAD"]).trim();
  const defaultBranch = originHead || (currentBranch && currentBranch !== "HEAD" ? currentBranch : "main");
  const tracked = listTrackedFiles(root);
  const trackedSet = new Set(tracked);
  const s = scanTrackedRepoFiles(root, tracked, trackedSet);
  const secondHop = new Set<string>();
  for (const rel of s.linkedScriptSet) {
    for (const next of extractWorkflowLinks(readBounded(path.join(root, rel), 8_000), trackedSet)) secondHop.add(next);
  }
  for (const rel of secondHop) s.linkedScriptSet.add(rel);
  const linkedArtifacts = [...s.linkedScriptSet].slice(0, 45).map((rel) => ({ path: rel, content: readBounded(path.join(root, rel), 10_000) }));
  const topDirLangs = [...s.dirLangCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 60).map(([k, count]) => {
    const [dir = "", lang = ""] = k.split("::");
    return { dir, lang, files: count };
  });
  const testDirs = new Map<string, number>();
  for (const tf of s.testFiles) {
    const key = tf.split("/").slice(0, 2).join("/");
    testDirs.set(key, (testDirs.get(key) ?? 0) + 1);
  }
  return {
    schemaVersion: 1,
    repoPath: root,
    repoName: path.basename(root),
    commitSha,
    defaultBranch,
    totalTrackedFiles: tracked.length,
    languageCensus: Object.fromEntries([...s.langCounts.entries()].sort((a, b) => b[1] - a[1])),
    topDirectoriesByLanguage: topDirLangs,
    symlinks: {
      total: s.symlinks.length,
      docOrAgent: s.symlinks.filter((x) => x.kind === "doc-or-agent").map((x) => x.path).slice(0, 25),
      code: s.symlinks.filter((x) => x.kind === "code").map((x) => x.path).slice(0, 25),
    },
    manifests: s.manifests,
    workflows: s.workflows,
    linkedCiArtifacts: linkedArtifacts,
    testSurface: {
      totalTestFiles: s.testFiles.length,
      inlineRustTestFilesCount: s.inlineRustTestFiles.length,
      inlineRustTestSample: s.inlineRustTestFiles.slice(0, 25),
      topTestDirectories: [...testDirs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 35),
      verificationSignals: Object.fromEntries(s.signalHits.entries()),
    },
  };
}

if (import.meta.main) {
  const target = process.argv[2];
  const outPath = process.argv[3];
  if (!target) {
    console.error("Usage: bun scripts/calibration/harvest.ts <repo-path> [out.json]");
    process.exit(1);
  }
  const packet = harvestRepoEvidence(target);
  const json = JSON.stringify(packet, null, 2);
  if (outPath) {
    fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
    fs.writeFileSync(outPath, json, "utf8");
    console.log(`Wrote evidence packet for ${packet.repoName}@${packet.commitSha.slice(0, 7)} (${packet.totalTrackedFiles} files, ${packet.workflows.length} workflows) -> ${outPath}`);
  } else {
    console.log(json);
  }
}
