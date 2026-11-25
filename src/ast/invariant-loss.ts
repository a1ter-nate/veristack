import type { ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";
import type { DiffLineEvent } from "../zero-defect/anti-evasion.ts";

const PY_IPV6_HOST_HEADER = /headers\s*\[\s*["']Host["']\s*\]\s*=\s*[^\n]*(?:\.hostname|host\b)/gi;
const PY_CACHE_NONE_TO_EMPTY = /\bif\s+([A-Za-z_][A-Za-z0-9_]*)\s+is\s+None\s*:\s*\r?\n[ \t]+\1\s*=\s*(?:""|'')/g;
const TS_STACK_DEPTH_POP = /\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)\.length\s*;([\s\S]{1,360}?)\2\.pop\s*\(\s*\)/g;
const GO_SLICE_LEN_PLUS_ONE = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*len\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)\s*\+\s*1\s*:/g;
const PY_ERROR_SUFFIX_FILTER = /\.endswith\s*\(\s*["']Error["']\s*\)/g;

const TEST_OR_DOC_PATH =
  /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.go$|(?:^|\/)(?:tests?\.rs|test_[^/]+\.py|[^/]*tests?\.cs|[^/]*_tests?\.rs)$|\.(?:md|mdx|txt|rst|json|lock|yaml|yml)$|(?:^|\/)(?:tests?|__tests__|fixtures|examples)\/)/i;

interface InvariantClass {
  name: string;
  regex: RegExp;
}

const INVARIANT_CLASSES: readonly InvariantClass[] = [
  {
    name: "null-nil-guard",
    regex: /(?:!==?\s*(?:null|undefined)\b|===?\s*(?:null|undefined)\b|\bis\s+(?:not\s+)?None\b|!=\s*nil\b|==\s*nil\b|\bif\s+let\s+(?:Some|Ok)\s*\(|\b(?:is_some|is_none|HasValue|IsNullOrEmpty|IsNullOrWhiteSpace)\s*\()|\?\.(?=[A-Za-z_$])/,
  },
  {
    name: "bounds-length-guard",
    regex: /\b(?:len\s*\([^)]+\)\s*(?:>|<|>=|<=|==|!=)|\.length\s*(?:>|<|>=|<=|==|!=)|\.is_empty\s*\(\s*\)|\.Count\s*(?:>|<|>=|<=|==|!=)|Math\.(?:min|max|Min|Max|Clamp)\s*\(|\.clamp\s*\(|(?:checked|saturating)_(?:add|sub|mul|div|duration_since)\s*\()/,
  },
  {
    name: "error-check-guard",
    regex: /\b(?:if\s+err\s*!=\s*nil|errors\.(?:As|Is)\s*\(|if\s+let\s+Err\s*\(|catch\s*\(|except\s+[A-Za-z_(]|issubclass\s*\([^)]*BaseException)/,
  },
  {
    name: "cleanup-unwind-guard",
    regex: /\b(?:finally\s*[:{]|defer\s+[A-Za-z_]|impl\b[^{;\n]*\bDrop\s+for\b|(?:await\s+)?using\s*(?:\(|var\b)|trap\s+['"]|with\s+open\s*\()/,
  },
  {
    name: "concurrency-lock-guard",
    regex: /\b(?:Mutex|RwLock|RLock|compare_exchange|CompareAndSwap|Interlocked\.|Ordering::|sync\.Once|wait_while\s*\()/,
  },
  {
    name: "timeout-cancel-guard",
    regex: /\b(?:AbortSignal|AbortController|WithTimeout|WithCancel|CancellationToken|timeout_at|max-time|lock_timeout|CONCURRENTLY|cancelled\s*\(\s*\))/,
  },
  {
    name: "auth-tenant-guard",
    regex: /\b(?:authorize|hasPermission|verify_?signature|verifySignature|auth\.uid\s*\(|StatusUnauthorized|StatusForbidden|tenant_id|tenantId|csrf|REVOKE\s+EXECUTE|search_path)/i,
  },
  {
    name: "defensive-copy-guard",
    regex: /\b(?:\.clone\s*\(\s*\)|\.slice\s*\(\s*\)|deepcopy\s*\(|Array\.from\s*\(|structuredClone\s*\(|\.to_vec\s*\(\s*\)|\.to_owned\s*\(\s*\))/,
  },
  {
    name: "deterministic-order-guard",
    regex: /\b(?:ORDER\s+BY\b|BTreeMap|BTreeSet|IndexMap|\.sort_by\s*\(|\.sort_unstable|slices\.Sort|sort\.Slice)/,
  },
  {
    name: "encoding-utf8-guard",
    regex: /\b(?:is_char_boundary|floor_char_boundary|encoding\s*=\s*["']utf-?8["']|from_utf8_lossy|to_string_lossy|Buffer\.byteLength|UTF8Encoding\s*\(\s*false)/,
  },
  {
    name: "input-canonicalize-guard",
    regex: /\b(?:path\.Clean|canonicalize|realpath|EvalSymlinks|escapeRegExp|RegExp\.escape|IsLocalUrl|posix\.normalize|fileURLToPath|to_file_path)/,
  },
  {
    name: "float-nan-finite-guard",
    regex: /\b(?:Number\.isNaN|Number\.isFinite|math\.isnan|math\.IsNaN|double\.IsNaN|float\.IsNaN|\.is_nan\s*\(\s*\)|\.is_finite\s*\(\s*\)|total_cmp\s*\()/,
  },
  {
    name: "type-shape-guard",
    regex: /\b(?:typeof\s+[A-Za-z_$][A-Za-z0-9_$.]*\s*[!=]==?|instanceof\s+[A-Z]|isinstance\s*\(|issubclass\s*\(|ast\.Is[A-Z]|matches!\s*\()/,
  },
  {
    name: "early-return-guard",
    regex: /^\s*if\b[^\n]{1,120}(?:\breturn\b|\bcontinue\b|\bbreak\b|\bthrow\b|\braise\b)/,
  },
  {
    name: "nullish-fallback-guard",
    regex: /\?\?(?!=)|\b(?:unwrap_or|unwrap_or_else|unwrap_or_default|ok_or|ok_or_else)\s*\(/,
  },
];

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
  findings.push({ id: `INV:${rule}:${file}:${line}`, rule, category: "structure", rung, severity, file, line, message, fix });
}

function isCommentLine(raw: string): boolean {
  const t = raw.trim();
  return !t || t.startsWith("//") || t.startsWith("/*") || t.startsWith("*") || t.startsWith("#") || t.startsWith("--");
}

function classifyLineInvariants(codeLine: string): Set<string> {
  const found = new Set<string>();
  for (const inv of INVARIANT_CLASSES) {
    if (inv.regex.test(codeLine)) found.add(inv.name);
  }
  return found;
}

export function analyzeInvariantGuards(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  if (!file.language || file.isTest) return findings;
  const raw = file.content;
  const code = maskCode(raw, file.language);
  const cfgTestIdx = file.language === "rust" ? raw.search(/#\[cfg\(test\)\]/) : -1;
  const prodCode = cfgTestIdx >= 0 ? code.slice(0, cfgTestIdx) : code;
  const prodRaw = cfgTestIdx >= 0 ? raw.slice(0, cfgTestIdx) : raw;

  if (file.language === "python") {
    for (const m of prodRaw.matchAll(PY_IPV6_HOST_HEADER)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodRaw.slice(Math.max(0, idx - 320), idx + 220);
      if (/":" in|':' in|\[.*\]|bracket|ipaddress|IPv6/i.test(win)) continue;
      if (!/port|urlparse|resolved/i.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "http-ipv6-host-header-unbracketed", "R1", "warn",
        "Setting HTTP Host header from parsed hostname without bracketing IPv6 literals violates RFC 3986 §3.2.2.",
        "Wrap IPv6 hostnames containing ':' in brackets ('[host]') before assigning or appending ':port' to Host.",
      );
    }

    for (const m of prodRaw.matchAll(PY_CACHE_NONE_TO_EMPTY)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodRaw.slice(Math.max(0, idx - 220), idx + 360);
      if (!/\b(?:cache|hash|md5|sha256|digest|ctx\.update|META\.get|headers\.get)\b/i.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "cache-key-none-collides-empty", "R0", "error",
        `Collapsing missing value '${m[1]} is None' to empty string '' before cache-key hashing lets absent and empty headers collide (RFC 9111).`,
        "Emit a distinct sentinel marker (e.g. b'-,') for absent values instead of normalizing None to ''.",
      );
    }

    for (const m of prodRaw.matchAll(PY_ERROR_SUFFIX_FILTER)) {
      const idx = m.index ?? 0;
      if (prodCode[idx] === " ") continue;
      const win = prodCode.slice(Math.max(0, idx - 120), idx + 220);
      if (/\b(?:issubclass|BaseException|Exception)\b/.test(win)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "py-exception-class-name-check-no-issubclass", "R1", "warn",
        "Selecting exception classes by '.endswith(\"Error\")' alone matches non-Exception classes and crashes except clauses.",
        "Verify issubclass(obj, BaseException) alongside any name-based exception filter.",
      );
    }
    return findings;
  }

  if (file.language === "typescript" || file.language === "javascript") {
    for (const m of prodCode.matchAll(TS_STACK_DEPTH_POP)) {
      const idx = m.index ?? 0;
      const between = m[3] ?? "";
      if (!/\b[A-Za-z_$][A-Za-z0-9_$.]*\s*\([^)]*\)/.test(between)) continue;
      if (/\b(?:try\s*\{|catch\s*\(|finally\s*\{)/.test(between)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "stack-push-pop-missing-unwind-guard", "R1", "warn",
        `Stack/list '${m[2]}' saves depth '${m[1]}' and pops after an unguarded call — an exception skips unwind and corrupts stack state.`,
        "Wrap the nested call in try { ... } catch/finally { stack.length = depth; ... } so exceptions restore stack depth.",
      );
    }
    return findings;
  }

  if (file.language === "go") {
    for (const m of prodCode.matchAll(GO_SLICE_LEN_PLUS_ONE)) {
      const idx = m.index ?? 0;
      const target = m[1] ?? "";
      const prefix = m[2] ?? "";
      const before = prodCode.slice(Math.max(0, idx - 260), idx);
      if (before.includes(`len(${target})`) && before.includes(`len(${prefix})`)) continue;
      push(
        findings, file.rel, lineOf(raw, idx), "go-slice-index-len-plus-one-unchecked", "R1", "error",
        `Slicing '${target}[len(${prefix})+1:]' panics with slice bounds out of range when len(${target}) == len(${prefix}).`,
        `Guard with 'if len(${target}) > len(${prefix})' (or strings.CutPrefix) before slicing past +1.`,
      );
    }
  }

  return findings;
}

export function auditDiffInvariantLoss(events: readonly DiffLineEvent[]): Finding[] {
  const findings: Finding[] = [];
  const byFile = new Map<string, DiffLineEvent[]>();

  for (const ev of events) {
    if (TEST_OR_DOC_PATH.test(ev.file)) continue;
    if (isCommentLine(ev.raw)) continue;
    const list = byFile.get(ev.file) ?? [];
    list.push(ev);
    byFile.set(ev.file, list);
  }

  for (const [file, fileEvents] of byFile.entries()) {
    const hunks: DiffLineEvent[][] = [];
    for (const ev of fileEvents) {
      const cur = hunks[hunks.length - 1];
      const prev = cur?.[cur.length - 1];
      if (cur && prev && Math.abs(ev.line - prev.line) <= 15) {
        cur.push(ev);
      } else {
        hunks.push([ev]);
      }
    }

    const isWholeFileDeletion = fileEvents.every((e) => e.kind === "del") && fileEvents.length > 40;
    if (isWholeFileDeletion) continue;

    const reportedForFile = new Set<string>();
    for (const hunk of hunks) {
      const dels = hunk.filter((e) => e.kind === "del");
      const adds = hunk.filter((e) => e.kind === "add");
      if (dels.length === 0) continue;

      const addedInvariants = new Set<string>();
      for (const a of adds) {
        for (const inv of classifyLineInvariants(a.code)) addedInvariants.add(inv);
      }

      for (const d of dels) {
        const lost = classifyLineInvariants(d.code);
        for (const inv of lost) {
          if (addedInvariants.has(inv) || reportedForFile.has(inv)) continue;
          reportedForFile.add(inv);
          findings.push({
            id: `DIFF:inv-lost:${file}:${d.line}:${inv}`,
            rule: "diff-invariant-guard-dropped",
            category: "cheat",
            rung: "R0",
            severity: "warn",
            file,
            line: d.line,
            message: `Diff removed a '${inv}' invariant in ${file}:${d.line} without preserving an equivalent guard in the replacement lines.`,
            fix: `Restore the '${inv}' invariant or add a regression test proving the invariant is now enforced by types or a higher boundary.`,
          });
        }
      }
    }
  }

  return findings;
}

export function buildSyntheticRevertEvents(
  relPath: string,
  afterContent: string,
  beforeContent: string,
): DiffLineEvent[] {
  const afterLines = afterContent.split(/\r?\n/);
  const beforeLines = beforeContent.split(/\r?\n/);
  const afterCounts = new Map<string, number>();
  const beforeCounts = new Map<string, number>();
  for (const l of afterLines) {
    const t = l.trim();
    if (t) afterCounts.set(t, (afterCounts.get(t) ?? 0) + 1);
  }
  for (const l of beforeLines) {
    const t = l.trim();
    if (t) beforeCounts.set(t, (beforeCounts.get(t) ?? 0) + 1);
  }

  const events: DiffLineEvent[] = [];
  const consumedDel = new Map<string, number>();
  for (let i = 0; i < afterLines.length; i++) {
    const raw = afterLines[i] ?? "";
    const t = raw.trim();
    if (!t) continue;
    const extra = (afterCounts.get(t) ?? 0) - (beforeCounts.get(t) ?? 0);
    const seen = consumedDel.get(t) ?? 0;
    if (extra > 0 && seen < extra) {
      consumedDel.set(t, seen + 1);
      events.push({ file: relPath, line: i + 1, kind: "del", raw, code: raw });
    }
  }

  const consumedAdd = new Map<string, number>();
  for (let i = 0; i < beforeLines.length; i++) {
    const raw = beforeLines[i] ?? "";
    const t = raw.trim();
    if (!t) continue;
    const extra = (beforeCounts.get(t) ?? 0) - (afterCounts.get(t) ?? 0);
    const seen = consumedAdd.get(t) ?? 0;
    if (extra > 0 && seen < extra) {
      consumedAdd.set(t, seen + 1);
      events.push({ file: relPath, line: i + 1, kind: "add", raw, code: raw });
    }
  }

  events.sort((a, b) => a.line - b.line);
  return events;
}
