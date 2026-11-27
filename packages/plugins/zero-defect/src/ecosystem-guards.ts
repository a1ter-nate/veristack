import path from "node:path";
import { isAstNode, parseTsAst, scanSfcScriptSpans, walkAst } from "@veristack/plugin-lang-typescript";
import { lineOf, maskCode, type DiscoveredRepo, type Finding, type ScannedFile } from "@veristack/plugin";

const TS_ANY_ANNOTATION = /(?:[,({]\s*[A-Za-z_$][A-Za-z0-9_$]*\??\s*:\s*any\b|\)\s*:\s*any\b|<\s*any\s*>)/g;
const UNBOUNDED_FETCH = /(?<![.\w$])fetch\s*\(\s*[^,)\n]+\s*\)/g;
const DYNAMIC_IMPORT_VAR = /\bimport\s*\(\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\)/g;
const ARGV_EMPTY_ONLY = /\bprocess\.argv\s*\[\s*\d+\s*\]\s*!==?\s*(?:""|'')/g;
const EVALUATOR_PASS_LITERAL = /\bstatus\s*:\s*["']pass["']/g;
const ZOD_TUPLE_CALL = /\bz\s*\.\s*tuple\s*\(/g;
const DUMMY_DATA_IDENT = /\b(?:dummyData|mockData|fakeData|placeholderData)\b/g;
const POPSTATE_LISTENER = /\baddEventListener\s*\(\s*["']popstate["'][\s\S]{0,400}?\bpushState\s*\(/g;
const WORKER_FETCH_REDIRECT_ERROR = /\bfetch\s*\([\s\S]{0,220}?\bredirect\s*:\s*["']error["']/g;
const DATETIMEFORMAT_RAW_NEW_DATE = /\bDateTimeFormat\s*\([^)]*\)\s*\.\s*format\s*\(\s*new\s+Date\s*\(/g;
const RUST_ONCE_MUTEX_MAP = /\b(?:OnceLock|LazyLock)\s*<\s*(?:std::sync::)?Mutex\s*<\s*(?:HashMap|BTreeMap)\b/g;
const RUST_STD_MUTEX_IN_ASYNC = /\basync\s+fn\b[\s\S]{0,500}?\.lock\s*\(\s*\)\s*(?:\.unwrap\(\)|\?)[\s\S]{0,300}?\.await\b/g;
const ENV_REAL_SECRET = /\b(?:AIzaSy[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16})\b/g;
const SHORT_FIXED_OVERLAY_CSS = /(?:^|[}\s])(\.[a-z][a-z0-9_-]{0,2})\s*\{[^}]*position\s*:\s*fixed[^}]*inset\s*:\s*0/gim;
const DOCKER_CA_UPDATE = /\bupdate-ca-certificates\b/;

const PLUGIN_OR_LOADER_PATH = /(?:plugin|loader|reload|registry|runtime|server)/i;
const SCHEMA_OR_TOOL_PATH = /(?:tool|agent|mcp|schema|function-call)/i;
const WORKER_OR_EDGE_PATH = /(?:worker|edge|cloudflare|wrangler|middleware)/i;
const FIXTURE_OR_STORY_PATH = /(?:fixture|story|stories|demo|mock|sandbox|example|test|spec)/i;

interface EcoFindingInput {
  file: string;
  line: number;
  rule: string;
  rung: Finding["rung"];
  severity: Finding["severity"];
  message: string;
  fix: string;
}

function push(findings: Finding[], entry: EcoFindingInput): void {
  findings.push({ id: `EG:${entry.rule}:${entry.file}:${entry.line}`, category: "structure", ...entry });
}

function scanMigrationDuplicates(repo: DiscoveredRepo, findings: Finding[]): void {
  if (!Array.isArray(repo.allRelPaths)) return;
  if (repo.allRelPaths.length === 0) return;
  const byDir = new Map<string, Map<string, string[]>>();
  for (const rel of repo.allRelPaths) {
    if (!/(?:^|\/)migrations?\//i.test(rel) || !/\.sql$/i.test(rel)) continue;
    const dir = path.posix.dirname(rel);
    const base = path.posix.basename(rel);
    const prefixMatch = /^(\d{2,})[_-]/.exec(base);
    if (!prefixMatch?.[1]) continue;
    const dirMap = byDir.get(dir) ?? new Map<string, string[]>();
    const list = dirMap.get(prefixMatch[1]) ?? [];
    list.push(base);
    dirMap.set(prefixMatch[1], list);
    byDir.set(dir, dirMap);
  }
  for (const [dir, prefixes] of byDir.entries()) {
    for (const [prefix, files] of prefixes.entries()) {
      if (files.length < 2) continue;
      push(findings, { file: `${dir}/${files[0]}`, line: 1, rule: "migration-duplicate-prefix", rung: "R0", severity: "error", message: `Duplicate SQL migration prefix '${prefix}' in ${dir}/ (${files.join(", ")}).`, fix: "Renumber colliding migrations monotonically or adopt timestamp prefixes so parallel branches cannot collide." });
    }
  }
}

function scanSpecialAssetFiles(file: ScannedFile, hasTsRepo: boolean, findings: Finding[]): boolean {
  if (!file.content) return true;
  const raw = file.content;
  const baseLower = path.posix.basename(file.rel).toLowerCase();
  if (/^\.env\.(?:example|sample|template|dist)$/i.test(baseLower)) {
    for (const m of raw.matchAll(ENV_REAL_SECRET)) {
      if (/0{6,}|X{6,}|EXAMPLE|PLACEHOLDER/i.test(m[0] ?? "")) continue;
      push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "ci-no-real-key-in-env-example", rung: "R0", severity: "error", message: "Live-looking provider API key or credential committed in an .env template file.", fix: "Replace real tokens with obvious dummy placeholders (e.g. YOUR_API_KEY_HERE) and rotate the exposed key." });
    }
    return true;
  }
  if (baseLower === "dockerfile" || baseLower.startsWith("dockerfile.")) {
    const stages = raw.split(/^\s*FROM\s+/im).slice(1);
    for (const stage of stages.length > 0 ? stages : [raw]) {
      if (DOCKER_CA_UPDATE.test(stage) && /\bnode\b/i.test(stage) && !/--use-system-ca|NODE_EXTRA_CA_CERTS/.test(stage)) {
        push(findings, { file: file.rel, line: 1, rule: "docker-node-missing-system-ca", rung: "R4", severity: "warn", message: "Dockerfile stage updates system CA certificates for a Node image without setting NODE_OPTIONS=--use-system-ca or NODE_EXTRA_CA_CERTS.", fix: "Set ENV NODE_OPTIONS=--use-system-ca (Node 22.9+) or NODE_EXTRA_CA_CERTS so Node honors installed system CAs." });
        break;
      }
    }
    return true;
  }
  if (file.rel.endsWith(".css")) {
    for (const m of raw.matchAll(SHORT_FIXED_OVERLAY_CSS)) {
      push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "no-unscoped-fullscreen-overlay-class", rung: "R1", severity: "warn", message: `Short global CSS selector '${m[1]}' defines a fullscreen fixed overlay — accidental class reuse blacks out the UI.`, fix: "Use a descriptive scoped selector (e.g. .modal-backdrop-overlay) or CSS Modules." });
    }
    return true;
  }
  if ((file.rel.endsWith(".vue") || file.rel.endsWith(".svelte")) && hasTsRepo) {
    const sfcRaw = file.rawContent ?? raw;
    for (const sp of scanSfcScriptSpans(sfcRaw)) {
      if (!/\blang\s*=\s*["']tsx?["']/i.test(sp.attrs)) {
        push(findings, { file: file.rel, line: lineOf(sfcRaw, sp.bodyStart), rule: "vue-require-script-lang-ts", rung: "R1", severity: "warn", message: 'SFC <script> omits lang="ts" in a TypeScript repository, silently disabling template type checks.', fix: 'Add lang="ts" to <script> / <script setup> blocks.' });
      }
    }
  }
  return false;
}

function scanRustEcosystemGuards(file: ScannedFile, raw: string, prodMasked: string, findings: Finding[]): void {
  for (const m of prodMasked.matchAll(RUST_ONCE_MUTEX_MAP)) {
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "rust-async-mutex-read-cache", rung: "R1", severity: "warn", message: "Global Mutex<Map> read cache serializes concurrent readers on hot paths.", fix: "Use ArcSwap (RCU), RwLock, or DashMap for read-heavy shared caches." });
  }
  for (const m of prodMasked.matchAll(RUST_STD_MUTEX_IN_ASYNC)) {
    const snippet = m[0]; const lockIdx = snippet.search(/\.lock\s*\(\s*\)/); const awaitIdx = snippet.search(/\.await\b/);
    let closedBeforeAwait = false;
    if (lockIdx >= 0 && awaitIdx > lockIdx) {
      let depth = 0;
      for (let i = lockIdx; i < awaitIdx; i++) {
        if (snippet[i] === "{") depth += 1;
        else if (snippet[i] === "}" && --depth < 0) { closedBeforeAwait = true; break; }
      }
    }
    if (closedBeforeAwait) continue;
    push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "rust-async-mutex-read-cache", rung: "R1", severity: "error", message: "Synchronous Mutex lock held across an .await point inside an async fn risks executor deadlocks.", fix: "Drop the MutexGuard in an inner block before .await or switch to tokio::sync::Mutex / ArcSwap." });
  }
}

function scanTsJsEcosystemCore(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  if (!masked) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  if (file.language === "typescript") {
    let anyCount = 0;
    for (const m of masked.matchAll(TS_ANY_ANNOTATION)) {
      if (++anyCount > 5) break;
      push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "no-any-type-annotation", rung: "R0", severity: "error", message: `Explicit 'any' type annotation (${m[0].trim()}) disables type checking and hides silent property typos.`, fix: "Replace 'any' with a concrete interface, generic type parameter, or 'unknown' parsed at the boundary." });
    }
  }
  if (!/\b(?:AbortSignal\.timeout|AbortController)\b/.test(masked)) {
    const rawLines = raw.split(/\r?\n/); let fetchCount = 0;
    for (const m of masked.matchAll(UNBOUNDED_FETCH)) {
      const idx = m.index ?? 0;
      if (/\b(?:signal|timeout)\b/.test(rawLines[lineOf(raw, idx) - 1] ?? "")) continue;
      if (++fetchCount > 3) break;
      push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "require-bounded-external-await", rung: "R1", severity: "warn", message: "Bare fetch(url) without an AbortSignal timeout can hang handlers or CI jobs indefinitely.", fix: "Pass { signal: AbortSignal.timeout(ms) } or thread an explicit AbortSignal." });
    }
  }
  if (PLUGIN_OR_LOADER_PATH.test(file.rel)) {
    for (const m of masked.matchAll(DYNAMIC_IMPORT_VAR)) {
      const idx = m.index ?? 0;
      if (/\?(?:mtime|v|t|bust|hash)=/.test(raw.slice(Math.max(0, idx - 180), idx + 120))) continue;
      push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "esm-dynamic-import-no-cache-bust", rung: "R1", severity: "warn", message: `Dynamic ESM import(${m[1]}) in loader/runtime lacks cache-busting query (?mtime=), risking stale module graph skew on reload.`, fix: "Append a content hash or file mtime query parameter when dynamically loading reloadable modules." });
    }
  }
  const rawLines = raw.split(/\r?\n/);
  for (const m of masked.matchAll(/\bprocess\.argv\s*\[\s*\d+\s*\]\s*!==?/g)) {
    const line = lineOf(raw, m.index ?? 0); const lineText = rawLines[line - 1] ?? "";
    if (!ARGV_EMPTY_ONLY.test(lineText)) continue;
    ARGV_EMPTY_ONLY.lastIndex = 0;
    if (/!==?\s*undefined|typeof\s+process\.argv|\?\?/.test(lineText)) continue;
    push(findings, { file: file.rel, line, rule: "cli-argv-unguarded-empty-check", rung: "R1", severity: "error", message: "Checking process.argv[N] !== '' without checking undefined treats missing CLI args as truthy and coerces them to 'undefined'.", fix: "Guard with typeof arg === 'string' && arg.length > 0 or use node:util parseArgs." });
  }
  for (const m of raw.matchAll(EVALUATOR_PASS_LITERAL)) {
    const idx = m.index ?? 0;
    if (masked[idx] === " ") continue;
    const win = raw.slice(Math.max(0, idx - 260), idx + 200);
    if (/\b(?:violators|violations)\b/.test(win) && !/\b(?:violators|violations)\.length\s*(?:===?|<=?|>)\s*0/.test(win)) {
      push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "evaluator-pass-with-violators", rung: "R0", severity: "error", message: 'Evaluator returns hardcoded status: "pass" while referencing violators/violations without gating on length === 0.', fix: 'Derive status from violators.length === 0 ? "pass" : "fail" so evaluators fail closed.' });
    }
  }
}

function scanTsJsEcosystemUiAndEdge(file: ScannedFile, raw: string, masked: string, findings: Finding[]): void {
  if (!masked) return;
  if (!file.rel) throw new Error("ScannedFile must have rel.");
  if (SCHEMA_OR_TOOL_PATH.test(file.rel)) {
    for (const m of masked.matchAll(ZOD_TUPLE_CALL)) {
      push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "llm-tool-schema-no-tuple", rung: "R1", severity: "warn", message: "z.tuple() compiles to JSON Schema array-valued items: [...], which LLM tool-calling APIs reject at runtime.", fix: "Use z.array(itemSchema).length(n) or a named z.object({...}) for tool/structured-output schemas." });
    }
  }
  if (!FIXTURE_OR_STORY_PATH.test(file.rel) && /\.(?:[jt]sx)$/.test(file.rel)) {
    for (const m of masked.matchAll(DUMMY_DATA_IDENT)) {
      push(findings, { file: file.rel, line: lineOf(raw, m.index ?? 0), rule: "ui-no-dummy-data-in-prod", rung: "R0", severity: "error", message: `Production UI component references placeholder/demo fixture '${m[0]}'.`, fix: "Remove demo/mock data from production components and render explicit loading/empty states instead." });
      break;
    }
    const jsxAst = parseTsAst(file);
    if (jsxAst) {
      let flaggedAnchor = false;
      walkAst(jsxAst, (node) => {
        if (node.type !== "JSXOpeningElement" || !isAstNode(node.name) || node.name.type !== "JSXIdentifier") return;
        const tag = typeof node.name.name === "string" ? node.name.name : "";
        const attrs = Array.isArray(node.attributes) ? node.attributes : [];
        if (tag === "a" && !flaggedAnchor && !attrs.some((a) => isAstNode(a) && (a.type === "JSXSpreadAttribute" || (a.type === "JSXAttribute" && isAstNode(a.name) && a.name.type === "JSXIdentifier" && (a.name.name === "href" || a.name.name === "render"))))) {
          flaggedAnchor = true;
          push(findings, { file: file.rel, line: lineOf(raw, node.start ?? 0), rule: "ui-anchor-without-href", rung: "R1", severity: "warn", message: "JSX <a> element omits href, breaking keyboard navigation and screen-reader semantics.", fix: "Add a valid href or use a semantic <button type='button'> for in-page actions." });
        }
        if (tag === "option" && attrs.some((a) => isAstNode(a) && a.type === "JSXAttribute" && isAstNode(a.name) && a.name.type === "JSXIdentifier" && a.name.name === "selected")) {
          push(findings, { file: file.rel, line: lineOf(raw, node.start ?? 0), rule: "react-option-selected", rung: "R1", severity: "warn", message: "React <option selected> triggers runtime warnings and breaks controlled <select> state.", fix: "Set value or defaultValue on the parent <select> element instead of selected on <option>." });
        }
      });
    }
  }
  for (const m of raw.matchAll(POPSTATE_LISTENER)) {
    const idx = m.index ?? 0;
    if (masked[idx] !== " ") push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "ui-popstate-pushstate-loop", rung: "R1", severity: "error", message: "popstate listener calls history.pushState(), creating Back-button navigation loops.", fix: "Sync router state passively inside popstate or use history.replaceState guarded by a URL diff." });
  }
  if (WORKER_OR_EDGE_PATH.test(file.rel) || /\b(?:ExportedHandler|ExecutionContext|Cloudflare)\b/.test(masked)) {
    for (const m of masked.matchAll(/\bfetch\s*\(/g)) {
      const idx = m.index ?? 0;
      if (!WORKER_FETCH_REDIRECT_ERROR.test(raw.slice(idx, idx + 220))) continue;
      WORKER_FETCH_REDIRECT_ERROR.lastIndex = 0;
      push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "worker-unsupported-fetch-redirect", rung: "R3", severity: "error", message: 'fetch(..., { redirect: "error" }) throws a runtime TypeError on edge runtimes (e.g. Cloudflare Workers) even when mocked tests pass.', fix: 'Use redirect: "manual" and explicitly reject 3xx responses, and run an R3 workerd/edge smoke test.' });
    }
  }
  for (const m of raw.matchAll(DATETIMEFORMAT_RAW_NEW_DATE)) {
    const idx = m.index ?? 0;
    if (masked[idx] === " " || /\b(?:isNaN|Number\.isNaN)\b/.test(raw.slice(Math.max(0, idx - 220), idx + 120))) continue;
    push(findings, { file: file.rel, line: lineOf(raw, idx), rule: "ui-unvalidated-date-parse", rung: "R1", severity: "warn", message: "Intl.DateTimeFormat().format(new Date(...)) without an isNaN guard throws RangeError on malformed or nullish timestamps.", fix: "Validate parsed dates with !Number.isNaN(date.getTime()) inside a central timestamp parser before formatting." });
  }
}

function scanFileEcosystemGuards(file: ScannedFile, hasTsRepo: boolean, findings: Finding[]): void {
  if (scanSpecialAssetFiles(file, hasTsRepo, findings)) return;
  if (!file.language || file.isTest || /\.d\.[cm]?ts$|\.pyi$/i.test(file.rel)) return;
  const raw = file.content;
  const masked = maskCode(raw, file.language, true);
  if (file.language === "rust") { scanRustEcosystemGuards(file, raw, masked, findings); return; }
  if (file.language !== "typescript" && file.language !== "javascript") return;
  scanTsJsEcosystemCore(file, raw, masked, findings);
  scanTsJsEcosystemUiAndEdge(file, raw, masked, findings);
}

export function analyzeEcosystemGuards(repo: DiscoveredRepo): Finding[] {
  const findings: Finding[] = [];
  const hasTsRepo = repo.languages.includes("typescript");
  scanMigrationDuplicates(repo, findings);
  for (const file of repo.files) {
    scanFileEcosystemGuards(file, hasTsRepo, findings);
  }
  return findings;
}
