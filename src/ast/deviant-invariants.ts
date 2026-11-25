import path from "node:path";
import type { DiscoveredRepo, ScannedFile } from "../discover.ts";
import { lineOf, maskCode } from "../test-lexical.ts";
import type { Finding } from "../types.ts";

const GENERATED_PATH = /(?:^|\/)(?:generated|generated-clients?|codegen|__snapshots__)\/|\.(?:gen|generated)\.[cm]?[jt]sx?$/i;
const SKIP_NULL_CALLEE = new Set([
  "get", "set", "has", "map", "filter", "reduce", "forEach", "push", "pop", "slice", "join", "split", "trim", "replace",
  "match", "test", "exec", "keys", "values", "entries", "from", "of", "isArray", "stringify", "parse", "resolve", "reject",
  "all", "race", "log", "warn", "error", "info", "debug", "min", "max", "floor", "ceil", "round", "abs", "now", "assign",
  "create", "freeze", "defineProperty", "readFileSync", "existsSync", "mkdirSync", "writeFileSync", "basename", "dirname",
  "extname", "relative", "toLowerCase", "toUpperCase", "startsWith", "endsWith", "includes", "indexOf", "substring", "concat",
  "sort", "reverse", "flat", "flatMap", "some", "every", "findIndex", "add", "delete", "clear", "size", "length",
]);

const ACQUIRE_CALL_RE =
  /\b([A-Za-z_$][A-Za-z0-9_$]*(?:acquire|Acquire|lock|Lock|lease|Lease|beginTx|BeginTx|startTransaction|StartTransaction|openSession|OpenSession)[A-Za-z0-9_$]*)\s*\(/g;

const ROUTE_DIR_RE = /(?:^|\/)(?:routes|controllers|handlers|endpoints|api)\b/i;
const PUBLIC_ROUTE_FILE =
  /(?:health|ready|live|metrics|status|ping|login|logout|signin|signout|signup|register|oauth|callback|webhook|public|index|mod|lib|types|schema|middleware|auth|common|shared|utils|helpers)\b/i;
const AUTH_GUARD_TOKEN =
  /\b(requireAuth|requireSession|requireAdmin|verifySession|verifyToken|verifyJwt|authenticate|authorize|checkPermission|ensureAuth|ensureTenant|authMiddleware|withAuth|getCurrentUser|get_current_user|require_auth|verify_session|AuthenticatedUser)\b/g;

interface CallSite {
  file: string;
  line: number;
  guarded: boolean;
  explicitNullish?: boolean;
}

function push(
  findings: Finding[],
  file: string,
  line: number,
  rule: string,
  message: string,
  fix: string,
): void {
  findings.push({
    id: `DEV:${rule}:${file}:${line}`,
    rule,
    category: "structure",
    rung: "R1",
    severity: "warn",
    file,
    line,
    message,
    fix,
  });
}

function isStatisticallyDeviant(checked: number, unchecked: number): boolean {
  const total = checked + unchecked;
  return total >= 4 && checked >= 3 && unchecked >= 1 && unchecked <= 2 && checked / total >= 0.75;
}

function isIdentChar(ch: string | undefined): boolean {
  return Boolean(ch && /[A-Za-z0-9_$]/.test(ch));
}

function inspectVarUsageAfter(after: string, varName: string): { isGuarded: boolean; explicitNullish: boolean; isUnsafeDeref: boolean } {
  let pos = after.indexOf(varName);
  let sawDeref = false;
  while (pos >= 0) {
    const prev = pos > 0 ? after[pos - 1] : "";
    const next = after[pos + varName.length];
    if (!isIdentChar(prev) && !isIdentChar(next)) {
      const beforeSlice = after.slice(Math.max(0, pos - 36), pos);
      const afterSlice = after.slice(pos + varName.length, pos + varName.length + 28);
      const explicitNullish = /^\s*(?:\?\.|\?\?|===?\s*(?:null|undefined)\b|!==?\s*(?:null|undefined)\b)/.test(afterSlice);
      if (
        explicitNullish ||
        /\bif\s*\(\s*!?\s*$/.test(beforeSlice) ||
        /(?:&&|\|\|)\s*!?\s*$/.test(beforeSlice) ||
        /\b(?:is|has)[A-Z][A-Za-z0-9_]*\s*\(\s*$/.test(beforeSlice) ||
        /^\s*(?:&&|\?(?!\?|\.))/.test(afterSlice) ||
        (/!\s*$/.test(beforeSlice) && /^\s*\|\|/.test(afterSlice))
      ) {
        return { isGuarded: true, explicitNullish, isUnsafeDeref: false };
      }
      if (/^\.[A-Za-z_$]/.test(afterSlice)) {
        sawDeref = true;
      }
    }
    pos = after.indexOf(varName, pos + varName.length);
  }
  return { isGuarded: false, explicitNullish: false, isUnsafeDeref: sawDeref };
}

function mineNullCheckBeliefs(files: readonly ScannedFile[], findings: Finding[]): void {
  const callsByFn = new Map<string, CallSite[]>();
  const assignCallRe =
    /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:await\s+)?(?:[A-Za-z_$][A-Za-z0-9_$.]*\.)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^;\n]*\)/g;

  for (const file of files) {
    if (file.language !== "typescript" && file.language !== "javascript") continue;
    const masked = maskCode(file.content, file.language);
    for (const m of masked.matchAll(assignCallRe)) {
      const varName = m[1] ?? "";
      const fnName = m[2] ?? "";
      if (!varName || !fnName || fnName.length < 4 || SKIP_NULL_CALLEE.has(fnName)) continue;
      if (!/^(?:find|lookup|get|load|fetch|read|parse|resolve|match|select|query)[A-Z]/.test(fnName)) continue;

      const idx = m.index ?? 0;
      const after = masked.slice(idx + m[0].length, idx + m[0].length + 280);
      const { isGuarded, explicitNullish, isUnsafeDeref } = inspectVarUsageAfter(after, varName);
      if (!isGuarded && !isUnsafeDeref) continue;

      const arr = callsByFn.get(fnName) ?? [];
      arr.push({ file: file.rel, line: lineOf(file.content, idx), guarded: isGuarded, explicitNullish });
      callsByFn.set(fnName, arr);
    }
  }

  for (const [fnName, sites] of callsByFn.entries()) {
    const guarded = sites.filter((s) => s.guarded);
    const unguarded = sites.filter((s) => !s.guarded);
    if (!guarded.some((s) => s.explicitNullish)) continue;
    if (!isStatisticallyDeviant(guarded.length, unguarded.length)) continue;
    for (const bad of unguarded) {
      push(
        findings,
        bad.file,
        bad.line,
        "invariant-deviant-null-check",
        `Deviant belief: '${fnName}()' is null-checked at ${guarded.length}/${sites.length} call sites in this repo, but dereferenced unchecked here.`,
        `Check the return value of '${fnName}()' for null/undefined (or use optional chaining) consistent with sibling call sites.`,
      );
    }
  }
}

function minePairedCleanupBeliefs(files: readonly ScannedFile[], findings: Finding[]): void {
  const sitesByFn = new Map<string, CallSite[]>();

  for (const file of files) {
    if (file.language !== "typescript" && file.language !== "javascript" && file.language !== "go" && file.language !== "python") {
      continue;
    }
    const masked = maskCode(file.content, file.language);
    for (const m of masked.matchAll(ACQUIRE_CALL_RE)) {
      const fnName = m[1] ?? "";
      if (!fnName || fnName.length < 5) continue;
      const idx = m.index ?? 0;
      const lineStart = masked.lastIndexOf("\n", idx) + 1;
      const prefix = masked.slice(lineStart, idx);
      if (/\b(?:function|def|func|class|interface|type)\s+$/.test(prefix)) continue;

      const win = masked.slice(Math.max(0, idx - 80), idx + 450);
      const guarded =
        file.language === "go"
          ? /\bdefer\b/.test(win)
          : file.language === "python"
            ? /\b(?:finally\s*:|with\s+)/.test(win)
            : /\b(?:finally\s*\{|using\s+)/.test(win);

      const arr = sitesByFn.get(fnName) ?? [];
      arr.push({ file: file.rel, line: lineOf(file.content, idx), guarded });
      sitesByFn.set(fnName, arr);
    }
  }

  for (const [fnName, sites] of sitesByFn.entries()) {
    const guarded = sites.filter((s) => s.guarded);
    const unguarded = sites.filter((s) => !s.guarded);
    if (!isStatisticallyDeviant(guarded.length, unguarded.length)) continue;
    for (const bad of unguarded) {
      push(
        findings,
        bad.file,
        bad.line,
        "invariant-deviant-paired-cleanup",
        `Deviant belief: '${fnName}()' is paired with finally/defer/using cleanup at ${guarded.length}/${sites.length} call sites, but unguarded here.`,
        `Wrap '${fnName}()' in try/finally, defer, or using/with so the acquired resource always releases on error paths.`,
      );
    }
  }
}

function mineRouteAuthBeliefs(files: readonly ScannedFile[], findings: Finding[]): void {
  const routeGroups = new Map<string, ScannedFile[]>();
  for (const file of files) {
    const dir = path.posix.dirname(file.rel);
    if (!ROUTE_DIR_RE.test(dir)) continue;
    const base = path.posix.basename(file.rel, path.posix.extname(file.rel));
    if (PUBLIC_ROUTE_FILE.test(base)) continue;
    const list = routeGroups.get(dir) ?? [];
    list.push(file);
    routeGroups.set(dir, list);
  }

  for (const [dir, group] of routeGroups.entries()) {
    if (group.length < 4) continue;
    const tokenPresence = new Map<string, Set<string>>();
    for (const file of group) {
      const masked = maskCode(file.content, file.language);
      for (const m of masked.matchAll(AUTH_GUARD_TOKEN)) {
        const tok = m[1] ?? "";
        if (!tok) continue;
        const set = tokenPresence.get(tok) ?? new Set<string>();
        set.add(file.rel);
        tokenPresence.set(tok, set);
      }
    }

    let dominantToken = "";
    let dominantFiles = new Set<string>();
    for (const [tok, set] of tokenPresence.entries()) {
      if (set.size > dominantFiles.size) {
        dominantToken = tok;
        dominantFiles = set;
      }
    }
    if (!dominantToken) continue;

    const missing = group.filter((f) => !dominantFiles.has(f.rel));
    if (!isStatisticallyDeviant(dominantFiles.size, missing.length)) continue;

    for (const outlier of missing) {
      push(
        findings,
        outlier.rel,
        1,
        "invariant-deviant-route-auth",
        `Deviant belief: ${dominantFiles.size}/${group.length} sibling route files in '${dir}/' enforce '${dominantToken}', but '${outlier.rel}' omits it.`,
        `Enforce '${dominantToken}' on this route handler or document/place intentionally public endpoints under a public route namespace.`,
      );
    }
  }
}

export function analyzeDeviantInvariants(repo: DiscoveredRepo): Finding[] {
  const prodFiles = repo.files.filter((f) => f.language && !f.isTest && !GENERATED_PATH.test(f.rel));
  if (prodFiles.length === 0) return [];
  const findings: Finding[] = [];
  mineNullCheckBeliefs(prodFiles, findings);
  minePairedCleanupBeliefs(prodFiles, findings);
  mineRouteAuthBeliefs(prodFiles, findings);
  return findings;
}
