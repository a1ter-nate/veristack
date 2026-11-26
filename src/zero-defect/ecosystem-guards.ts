import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const TS_ANY_ANNOTATION = /(?:[,({]\s*[A-Za-z_$][A-Za-z0-9_$]*\??\s*:\s*any\b|\)\s*:\s*any\b|<\s*any\s*>)/g;
const UNBOUNDED_FETCH = /\bfetch\s*\(\s*[^,)\n]+\s*\)/g;
const DYNAMIC_IMPORT_VAR = /\bimport\s*\(\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\)/g;
const ARGV_EMPTY_ONLY = /\bprocess\.argv\s*\[\s*\d+\s*\]\s*!==?\s*(?:""|'')/g;
const EVALUATOR_PASS_LITERAL = /\bstatus\s*:\s*["']pass["']/g;
const ZOD_TUPLE_CALL = /\bz\s*\.\s*tuple\s*\(/g;
const DUMMY_DATA_IDENT = /\b(?:dummyData|mockData|fakeData|placeholderData)\b/g;
const POPSTATE_LISTENER = /\baddEventListener\s*\(\s*["']popstate["'][\s\S]{0,400}?\bpushState\s*\(/g;
const JSX_ANCHOR_TAG = /<a\b([^>]*?)>/g;
const JSX_OPTION_SELECTED = /<option\b[^>]*\bselected(?:\s*=|\s|>)/g;
const WORKER_FETCH_REDIRECT_ERROR = /\bfetch\s*\([\s\S]{0,220}?\bredirect\s*:\s*["']error["']/g;
const DATETIMEFORMAT_RAW_NEW_DATE = /\bDateTimeFormat\s*\([^)]*\)\s*\.\s*format\s*\(\s*new\s+Date\s*\(/g;
const RUST_ONCE_MUTEX_MAP = /\b(?:OnceLock|LazyLock)\s*<\s*(?:std::sync::)?Mutex\s*<\s*(?:HashMap|BTreeMap)\b/g;
const RUST_STD_MUTEX_IN_ASYNC = /\basync\s+fn\b[\s\S]{0,500}?\.lock\s*\(\s*\)\s*(?:\.unwrap\(\)|\?)[\s\S]{0,300}?\.await\b/g;
const VUE_SCRIPT_NO_TS = /<script(?:\s+setup)?\s*>/g;
const ENV_REAL_SECRET = /\b(?:AIzaSy[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16})\b/g;
const SHORT_FIXED_OVERLAY_CSS = /(?:^|[}\s])(\.[a-z][a-z0-9_-]{0,2})\s*\{[^}]*position\s*:\s*fixed[^}]*inset\s*:\s*0/gim;
const DOCKER_CA_UPDATE = /\bupdate-ca-certificates\b/;

const PLUGIN_OR_LOADER_PATH = /(?:plugin|loader|reload|registry|runtime|server)/i;
const SCHEMA_OR_TOOL_PATH = /(?:tool|agent|mcp|schema|function-call)/i;
const WORKER_OR_EDGE_PATH = /(?:worker|edge|cloudflare|wrangler|middleware)/i;
const FIXTURE_OR_STORY_PATH = /(?:fixture|story|stories|demo|mock|sandbox|example|test|spec)/i;

function push(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  rung: Finding["rung"],
  severity: Finding["severity"],
  message: string,
  fix: string,
): void {
  findings.push({ id: `EG:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
}

function scanMigrationDuplicates(repo: DiscoveredRepo, findings: Finding[]): void {
  const byDir = new Map<string, Map<string, string[]>>();
  for (const rel of repo.allRelPaths) {
    if (!/(?:^|\/)migrations?\//i.test(rel) || !/\.sql$/i.test(rel)) continue;
    const dir = path.posix.dirname(rel);
    const base = path.posix.basename(rel);
    const prefixMatch = /^(\d{2,})[_-]/.exec(base);
    if (!prefixMatch?.[1]) continue;
    const prefix = prefixMatch[1];
    const dirMap = byDir.get(dir) ?? new Map<string, string[]>();
    const list = dirMap.get(prefix) ?? [];
    list.push(base);
    dirMap.set(prefix, list);
    byDir.set(dir, dirMap);
  }
  for (const [dir, prefixes] of byDir.entries()) {
    for (const [prefix, files] of prefixes.entries()) {
      if (files.length < 2) continue;
      push(
        findings,
        `${dir}/${files[0]}`,
        1,
        "migration-duplicate-prefix",
        "R0",
        "error",
        `Duplicate SQL migration prefix '${prefix}' in ${dir}/ (${files.join(", ")}).`,
        "Renumber colliding migrations monotonically or adopt timestamp prefixes so parallel branches cannot collide.",
      );
    }
  }
}

function scanFileEcosystemGuards(file: ScannedFile, hasTsRepo: boolean, findings: Finding[]): void {
  const raw = file.content;
  const baseLower = path.posix.basename(file.rel).toLowerCase();

  if (/^\.env\.(?:example|sample|template|dist)$/i.test(baseLower)) {
    for (const m of raw.matchAll(ENV_REAL_SECRET)) {
      const tok = m[0] ?? "";
      if (/0{6,}|X{6,}|EXAMPLE|PLACEHOLDER/i.test(tok)) continue;
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "ci-no-real-key-in-env-example",
        "R0",
        "error",
        "Live-looking provider API key or credential committed in an .env template file.",
        "Replace real tokens with obvious dummy placeholders (e.g. YOUR_API_KEY_HERE) and rotate the exposed key.",
      );
    }
    return;
  }

  if (baseLower === "dockerfile" || baseLower.startsWith("dockerfile.")) {
    const stages = raw.split(/^\s*FROM\s+/im).slice(1);
    for (const stage of stages.length > 0 ? stages : [raw]) {
      if (DOCKER_CA_UPDATE.test(stage) && /\bnode\b/i.test(stage) && !/--use-system-ca|NODE_EXTRA_CA_CERTS/.test(stage)) {
        push(
          findings,
          file.rel,
          1,
          "docker-node-missing-system-ca",
          "R4",
          "warn",
          "Dockerfile stage updates system CA certificates for a Node image without setting NODE_OPTIONS=--use-system-ca or NODE_EXTRA_CA_CERTS.",
          "Set ENV NODE_OPTIONS=--use-system-ca (Node 22.9+) or NODE_EXTRA_CA_CERTS so Node honors installed system CAs.",
        );
        break;
      }
    }
    return;
  }

  if (file.rel.endsWith(".css")) {
    for (const m of raw.matchAll(SHORT_FIXED_OVERLAY_CSS)) {
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "no-unscoped-fullscreen-overlay-class",
        "R1",
        "warn",
        `Short global CSS selector '${m[1]}' defines a fullscreen fixed overlay — accidental class reuse blacks out the UI.`,
        "Use a descriptive scoped selector (e.g. .modal-backdrop-overlay) or CSS Modules.",
      );
    }
    return;
  }

  if (file.rel.endsWith(".vue") && hasTsRepo) {
    const vueRaw = file.rawContent ?? raw;
    for (const m of vueRaw.matchAll(VUE_SCRIPT_NO_TS)) {
      push(
        findings,
        file.rel,
        lineOf(vueRaw, m.index ?? 0),
        "vue-require-script-lang-ts",
        "R1",
        "warn",
        'Vue SFC <script> omits lang="ts" in a TypeScript repository, silently disabling vue-tsc template checks.',
        'Add lang="ts" to <script> / <script setup> blocks.',
      );
    }
    return;
  }

  if (!file.language || file.isTest) return;

  const masked = maskCode(raw, file.language);

  if (file.language === "rust") {
    const cfgTestIdx = raw.search(/#\[cfg\(test\)\]/);
    const prodMasked = cfgTestIdx >= 0 ? masked.slice(0, cfgTestIdx) : masked;
    for (const m of prodMasked.matchAll(RUST_ONCE_MUTEX_MAP)) {
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "rust-async-mutex-read-cache",
        "R1",
        "warn",
        "Global Mutex<Map> read cache serializes concurrent readers on hot paths.",
        "Use ArcSwap (RCU), RwLock, or DashMap for read-heavy shared caches.",
      );
    }
    for (const m of prodMasked.matchAll(RUST_STD_MUTEX_IN_ASYNC)) {
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "rust-async-mutex-read-cache",
        "R1",
        "error",
        "Synchronous Mutex lock held across an .await point inside an async fn risks executor deadlocks.",
        "Drop the MutexGuard in an inner block before .await or switch to tokio::sync::Mutex / ArcSwap.",
      );
    }
    return;
  }

  if (file.language !== "typescript" && file.language !== "javascript") return;

  if (file.language === "typescript") {
    let anyCount = 0;
    for (const m of masked.matchAll(TS_ANY_ANNOTATION)) {
      if (++anyCount > 5) break;
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "no-any-type-annotation",
        "R0",
        "error",
        `Explicit 'any' type annotation (${m[0].trim()}) disables type checking and hides silent property typos.`,
        "Replace 'any' with a concrete interface, generic type parameter, or 'unknown' parsed at the boundary.",
      );
    }
  }

  if (!/\b(?:AbortSignal\.timeout|AbortController)\b/.test(masked)) {
    let fetchCount = 0;
    for (const m of masked.matchAll(UNBOUNDED_FETCH)) {
      const idx = m.index ?? 0;
      const lineText = raw.split(/\r?\n/)[lineOf(raw, idx) - 1] ?? "";
      if (/\b(?:signal|timeout)\b/.test(lineText)) continue;
      if (++fetchCount > 3) break;
      push(
        findings,
        file.rel,
        lineOf(raw, idx),
        "require-bounded-external-await",
        "R1",
        "warn",
        "Bare fetch(url) without an AbortSignal timeout can hang handlers or CI jobs indefinitely.",
        "Pass { signal: AbortSignal.timeout(ms) } or thread an explicit AbortSignal.",
      );
    }
  }

  if (PLUGIN_OR_LOADER_PATH.test(file.rel)) {
    for (const m of masked.matchAll(DYNAMIC_IMPORT_VAR)) {
      const idx = m.index ?? 0;
      const win = raw.slice(Math.max(0, idx - 180), idx + 120);
      if (/\?(?:mtime|v|t|bust|hash)=/.test(win)) continue;
      push(
        findings,
        file.rel,
        lineOf(raw, idx),
        "esm-dynamic-import-no-cache-bust",
        "R1",
        "warn",
        `Dynamic ESM import(${m[1]}) in loader/runtime lacks cache-busting query (?mtime=), risking stale module graph skew on reload.`,
        "Append a content hash or file mtime query parameter when dynamically loading reloadable modules.",
      );
    }
  }

  const rawLines = raw.split(/\r?\n/);
  for (const m of masked.matchAll(/\bprocess\.argv\s*\[\s*\d+\s*\]\s*!==?/g)) {
    const idx = m.index ?? 0;
    const line = lineOf(raw, idx);
    const lineText = rawLines[line - 1] ?? "";
    if (!ARGV_EMPTY_ONLY.test(lineText)) continue;
    ARGV_EMPTY_ONLY.lastIndex = 0;
    if (/!==?\s*undefined|typeof\s+process\.argv|\?\?/.test(lineText)) continue;
    push(
      findings,
      file.rel,
      line,
      "cli-argv-unguarded-empty-check",
      "R1",
      "error",
      "Checking process.argv[N] !== '' without checking undefined treats missing CLI args as truthy and coerces them to 'undefined'.",
      "Guard with typeof arg === 'string' && arg.length > 0 or use node:util parseArgs.",
    );
  }

  for (const m of raw.matchAll(EVALUATOR_PASS_LITERAL)) {
    const idx = m.index ?? 0;
    if (masked[idx] === " ") continue;
    const win = raw.slice(Math.max(0, idx - 260), idx + 200);
    if (/\b(?:violators|violations)\b/.test(win) && !/\b(?:violators|violations)\.length\s*(?:===?|<=?|>)\s*0/.test(win)) {
      push(
        findings,
        file.rel,
        lineOf(raw, idx),
        "evaluator-pass-with-violators",
        "R0",
        "error",
        'Evaluator returns hardcoded status: "pass" while referencing violators/violations without gating on length === 0.',
        'Derive status from violators.length === 0 ? "pass" : "fail" so evaluators fail closed.',
      );
    }
  }

  if (SCHEMA_OR_TOOL_PATH.test(file.rel)) {
    for (const m of masked.matchAll(ZOD_TUPLE_CALL)) {
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "llm-tool-schema-no-tuple",
        "R1",
        "warn",
        "z.tuple() compiles to JSON Schema array-valued items: [...], which LLM tool-calling APIs reject at runtime.",
        "Use z.array(itemSchema).length(n) or a named z.object({...}) for tool/structured-output schemas.",
      );
    }
  }

  if (!FIXTURE_OR_STORY_PATH.test(file.rel) && /\.(?:[jt]sx)$/.test(file.rel)) {
    for (const m of masked.matchAll(DUMMY_DATA_IDENT)) {
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "ui-no-dummy-data-in-prod",
        "R0",
        "error",
        `Production UI component references placeholder/demo fixture '${m[0]}'.`,
        "Remove demo/mock data from production components and render explicit loading/empty states instead.",
      );
      break;
    }

    for (const m of raw.matchAll(JSX_ANCHOR_TAG)) {
      const attrs = m[1] ?? "";
      if (!/\b(?:href|render)\s*=|\{\s*\.\.\./.test(attrs)) {
        push(
          findings,
          file.rel,
          lineOf(raw, m.index ?? 0),
          "ui-anchor-without-href",
          "R1",
          "warn",
          "JSX <a> element omits href, breaking keyboard navigation and screen-reader semantics.",
          "Add a valid href or use a semantic <button type='button'> for in-page actions.",
        );
        break;
      }
    }

    for (const m of raw.matchAll(JSX_OPTION_SELECTED)) {
      push(
        findings,
        file.rel,
        lineOf(raw, m.index ?? 0),
        "react-option-selected",
        "R1",
        "warn",
        "React <option selected> triggers runtime warnings and breaks controlled <select> state.",
        "Set value or defaultValue on the parent <select> element instead of selected on <option>.",
      );
    }
  }

  for (const m of raw.matchAll(POPSTATE_LISTENER)) {
    const idx = m.index ?? 0;
    if (masked[idx] === " ") continue;
    push(
      findings,
      file.rel,
      lineOf(raw, idx),
      "ui-popstate-pushstate-loop",
      "R1",
      "error",
      "popstate listener calls history.pushState(), creating Back-button navigation loops.",
      "Sync router state passively inside popstate or use history.replaceState guarded by a URL diff.",
    );
  }

  if (WORKER_OR_EDGE_PATH.test(file.rel) || /\b(?:ExportedHandler|ExecutionContext|Cloudflare)\b/.test(masked)) {
    for (const m of masked.matchAll(/\bfetch\s*\(/g)) {
      const idx = m.index ?? 0;
      if (!WORKER_FETCH_REDIRECT_ERROR.test(raw.slice(idx, idx + 220))) continue;
      WORKER_FETCH_REDIRECT_ERROR.lastIndex = 0;
      push(
        findings,
        file.rel,
        lineOf(raw, idx),
        "worker-unsupported-fetch-redirect",
        "R3",
        "error",
        'fetch(..., { redirect: "error" }) throws a runtime TypeError on edge runtimes (e.g. Cloudflare Workers) even when mocked tests pass.',
        'Use redirect: "manual" and explicitly reject 3xx responses, and run an R3 workerd/edge smoke test.',
      );
    }
  }

  for (const m of raw.matchAll(DATETIMEFORMAT_RAW_NEW_DATE)) {
    const idx = m.index ?? 0;
    if (masked[idx] === " ") continue;
    const win = raw.slice(Math.max(0, idx - 220), idx + 120);
    if (/\b(?:isNaN|Number\.isNaN)\b/.test(win)) continue;
    push(
      findings,
      file.rel,
      lineOf(raw, idx),
      "ui-unvalidated-date-parse",
      "R1",
      "warn",
      "Intl.DateTimeFormat().format(new Date(...)) without an isNaN guard throws RangeError on malformed or nullish timestamps.",
      "Validate parsed dates with !Number.isNaN(date.getTime()) inside a central timestamp parser before formatting.",
    );
  }
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
