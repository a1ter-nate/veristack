import {
  globMatchesPath,
  lineOf,
  loadRepoConfig,
  maskCode,
  type DiscoveredRepo,
  type Finding,
  type ScannedFile,
} from "@veristack/plugin";

const MUTATION_HINT = /\bthis\.[a-zA-Z_$]\w*\s*[+\-*/]?=|\.\s*(?:save|update|delete|insert|upsert|write|writeFileSync|commit|set|push|splice)\s*\(/;
const LOG_ONLY_HINT = /\b(?:console|logger|log)\s*\.\s*(?:log|warn|error|info|debug)\s*\(/;
const OVERBROAD_INVARIANT_TYPE = /\b(?:AssertionError|InvariantViolationError|TypeError|RangeError|ReferenceError)\b/;
const EXTERNAL_IO_CALL = /\bfetch\s*\(|\b(?:axios|stripe|resend|sendgrid|twilio|sqs|sns|s3|HttpClient)\s*\.[a-zA-Z_$]/;
const DB_TX_OPEN = /\b(?:db|tx|prisma|knex|sql|drizzle|client|pool|em|Effect)\s*\.\s*(?:\$?transaction|begin|withTransaction)\s*\(/g;

const PAVED_PATH_GROUPS: ReadonlyArray<{ concern: string; libs: readonly string[] }> = [
  { concern: "HTTP client", libs: ["axios", "got", "ky", "superagent", "node-fetch"] },
  { concern: "schema validation", libs: ["zod", "yup", "joi", "valibot", "arktype"] },
  { concern: "date/time", libs: ["moment", "dayjs", "date-fns", "luxon"] },
  { concern: "utility helpers", libs: ["lodash", "ramda", "underscore"] },
  { concern: "structured logging", libs: ["winston", "pino", "bunyan"] },
];

function extractBraceBlock(text: string, openIdx: number, maxLen = 1800): { body: string; end: number } | null {
  let depth = 0;
  const limit = Math.min(text.length, openIdx + maxLen);
  for (let i = openIdx; i < limit; i++) {
    if (text[i] === "{") depth += 1;
    else if (text[i] === "}" && --depth === 0) return { body: text.slice(openIdx + 1, i), end: i };
  }
  return null;
}

function checkBraceAspiratorPaths(file: ScannedFile, masked: string, findings: Finding[]): void {
  if (!masked) return;
  const raw = file.content;
  if (file.language === "typescript" || file.language === "javascript" || file.language === "csharp") {
    for (const m of masked.matchAll(/\bcatch\s*(?:\([^)]*\))?\s*\{/g)) {
      const idx = m.index ?? 0;
      const openIdx = idx + m[0].length - 1;
      const blk = extractBraceBlock(masked, openIdx);
      if (!blk) continue;
      const rawBody = raw.slice(openIdx + 1, blk.end);
      const line = lineOf(raw, idx);
      if (/(?:\/\/|\/\*)\s*(?:TODO|FIXME|XXX)\b/i.test(rawBody)) {
        findings.push({
          id: `ASP:todo:${file.rel}:${line}`, rule: "aspirator-todo-in-error-path", category: "structure", rung: "R0",
          severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
          message: "Unfinished TODO/FIXME inside catch block — Yuan et al. (Aspirator) show trivial error-path defects cause 92% of catastrophic failures.",
          fix: "Implement explicit fail-closed error handling, recovery, or propagation before merging.",
        });
      }
      const hasControlExit = /\b(?:throw|return|reject|fail|process\.exit|abort|rollback|compensate)\b/.test(blk.body);
      const trySlice = masked.slice(Math.max(0, idx - 500), idx);
      if (!hasControlExit && LOG_ONLY_HINT.test(blk.body) && /\btry\s*\{/.test(trySlice) && MUTATION_HINT.test(trySlice)) {
        findings.push({
          id: `ASP:log-continue:${file.rel}:${line}`, rule: "aspirator-log-and-continue-mutation", category: "structure", rung: "R0",
          severity: "warn", soundness: "incorrectness-witness", file: file.rel, line,
          message: "Catch block logs and continues after a state-mutating try block without rethrowing, rolling back, or failing closed.",
          fix: "Rethrow the error, return a typed failure result, or explicitly roll back state on failure.",
        });
      }
      if (OVERBROAD_INVARIANT_TYPE.test(blk.body) && !/\bthrow\b/.test(blk.body)) {
        findings.push({
          id: `ASP:invariant-catch:${file.rel}:${line}`, rule: "aspirator-overbroad-invariant-catch", category: "structure", rung: "R0",
          severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
          message: "Catch handler intercepts assertion/invariant/type error without rethrowing, masking programmer defects.",
          fix: "Re-throw assertion, invariant, TypeError, and RangeError defects immediately instead of swallowing them.",
        });
      }
    }
  }
  if (file.language === "rust") {
    for (const m of masked.matchAll(/\bErr\s*\([^)]*\)\s*=>\s*\{/g)) {
      const idx = m.index ?? 0;
      const openIdx = idx + m[0].length - 1;
      const blk = extractBraceBlock(masked, openIdx);
      if (!blk) continue;
      if (/(?:\/\/|\/\*)\s*(?:TODO|FIXME|XXX)\b/i.test(raw.slice(openIdx + 1, blk.end))) {
        const line = lineOf(raw, idx);
        findings.push({
          id: `ASP:todo-rs:${file.rel}:${line}`, rule: "aspirator-todo-in-error-path", category: "structure", rung: "R0",
          severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
          message: "Unfinished TODO/FIXME inside Rust Err(_) handler.",
          fix: "Propagate with '?' or implement complete fail-closed error handling.",
        });
      }
    }
  }
}

function checkPythonAspiratorPaths(file: ScannedFile, findings: Finding[]): void {
  if (file.language !== "python" || !file.content) return;
  const lines = file.content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i] ?? "";
    const exMatch = /^(\s*)except\b([^:]*):/.exec(ln);
    if (!exMatch) continue;
    const baseIndent = (exMatch[1] ?? "").length;
    const clause = exMatch[2] ?? "";
    const blockLines: string[] = [];
    for (let j = i + 1; j < lines.length && j < i + 25; j++) {
      const cur = lines[j] ?? "";
      if (cur.trim() && cur.length - cur.trimStart().length <= baseIndent) break;
      blockLines.push(cur);
    }
    const blockText = blockLines.join("\n");
    if (/#\s*(?:TODO|FIXME|XXX)\b/i.test(blockText)) {
      findings.push({
        id: `ASP:todo-py:${file.rel}:${i + 1}`, rule: "aspirator-todo-in-error-path", category: "structure", rung: "R0",
        severity: "error", soundness: "incorrectness-witness", file: file.rel, line: i + 1,
        message: "Unfinished TODO/FIXME inside Python except block.",
        fix: "Implement explicit fail-closed error handling or re-raise.",
      });
    }
    if (/\b(?:BaseException|AssertionError)\b/.test(clause) && !/\braise\b/.test(blockText)) {
      findings.push({
        id: `ASP:py-base:${file.rel}:${i + 1}`, rule: "aspirator-overbroad-invariant-catch", category: "structure", rung: "R0",
        severity: "error", soundness: "incorrectness-witness", file: file.rel, line: i + 1,
        message: "Python except catches BaseException/AssertionError without re-raising.",
        fix: "Catch specific recoverable Exception subclasses and never swallow AssertionError or BaseException.",
      });
    }
  }
}

function checkAspiratorErrorPaths(file: ScannedFile, masked: string, findings: Finding[]): void {
  checkBraceAspiratorPaths(file, masked, findings);
  checkPythonAspiratorPaths(file, findings);
}

function checkIoInsideDbTransaction(file: ScannedFile, masked: string, findings: Finding[]): void {
  if (file.language !== "typescript" && file.language !== "javascript") return;
  for (const m of masked.matchAll(DB_TX_OPEN)) {
    const idx = m.index ?? 0;
    const braceIdx = masked.indexOf("{", idx + m[0].length);
    if (braceIdx < 0 || braceIdx - idx > 120) continue;
    const blk = extractBraceBlock(masked, braceIdx, 2400);
    if (!blk || !EXTERNAL_IO_CALL.test(blk.body)) continue;
    const line = lineOf(file.content, idx);
    findings.push({
      id: `UNC:tx-io:${file.rel}:${line}`, rule: "io-inside-db-transaction", category: "structure", rung: "R0",
      severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
      message: "External HTTP/provider I/O invoked inside a database transaction — holds DB locks across network latency and breaks atomicity on partial failure.",
      fix: "Move external provider I/O outside the transaction or persist an outbox/intent row inside the transaction and dispatch asynchronously.",
    });
  }
}

function checkParseDontValidateAndGuards(file: ScannedFile, masked: string, findings: Finding[]): void {
  if (file.language !== "typescript" && file.language !== "javascript") return;
  const valRe = /\bexport\s+function\s+(validate[A-Z]\w*)\s*\(([^)]*)\)\s*:\s*(boolean|void)\s*\{/g;
  for (const m of masked.matchAll(valRe)) {
    const fnName = m[1] ?? "";
    const params = m[2] ?? "";
    const idx = m.index ?? 0;
    if (!/\b(?:unknown|string|Record|object|any)\b/.test(params)) continue;
    const blk = extractBraceBlock(masked, idx + m[0].length - 1, 1400);
    if (!blk || /\bthrow\b/.test(blk.body)) continue;
    const checks = (blk.body.match(/\b(?:typeof|Array\.isArray|Number\.isFinite)\b|\.\s*(?:test|length|startsWith|includes)\b/g) ?? []).length;
    if (checks >= 2) {
      const line = lineOf(file.content, idx);
      findings.push({
        id: `PDV:discard:${file.rel}:${line}`, rule: "validate-and-discard", category: "structure", rung: "R1",
        severity: "warn", soundness: "hygiene-lint", file: file.rel, line,
        message: `Function '${fnName}' validates untrusted input and discards proof by returning ${m[3]} without a type predicate or parsed value (Parse, Don't Validate).`,
        fix: `Return a parsed/branded domain type (or use a TypeScript 'input is ParsedType' type guard) so downstream layers cannot re-check or misuse raw input.`,
      });
    }
  }
  const guardCounts = new Map<string, { count: number; firstOffset: number }>();
  for (const m of masked.matchAll(/\bif\s*\(([^()\n]{20,90})\)\s*(?:throw|return)\b/g)) {
    const rawCond = (m[1] ?? "").replace(/\s+/g, " ").trim();
    if (!/(?:&&|\|\||\btypeof\b)/.test(rawCond)) continue;
    const prev = guardCounts.get(rawCond);
    if (prev) prev.count += 1;
    else guardCounts.set(rawCond, { count: 1, firstOffset: m.index ?? 0 });
  }
  for (const [cond, info] of guardCounts.entries()) {
    if (info.count < 4) continue;
    const line = lineOf(file.content, info.firstOffset);
    findings.push({
      id: `PDV:repeat:${file.rel}:${line}`, rule: "repeated-defensive-guard", category: "structure", rung: "R1",
      severity: "warn", soundness: "hygiene-lint", file: file.rel, line,
      message: `Identical defensive guard 'if (${cond.slice(0, 50)})' repeated ${info.count} times in ${file.rel} (compensating code across layers).`,
      fix: "Parse and validate once at the module boundary into a narrowed type so internal functions rely on the type instead of repeating guards.",
    });
    break;
  }
}

function checkImportsBackslidingAndCompeting(
  file: ScannedFile,
  retiring: ReadonlyArray<{ module: string; replacement?: string; allowedImporters?: readonly string[] }>,
  forbidNew: readonly string[],
  findings: Finding[],
): void {
  if (file.language !== "typescript" && file.language !== "javascript") return;
  const importedSpecs: Array<{ spec: string; offset: number }> = [];
  for (const m of file.content.matchAll(/^\s*import\b[^\n]*?\bfrom\s+["']([^"']+)["']|\brequire\s*\(\s*["']([^"']+)["']\s*\)/gm)) {
    const spec = (m[1] ?? m[2] ?? "").trim();
    if (spec) importedSpecs.push({ spec, offset: m.index ?? 0 });
  }
  if (importedSpecs.length === 0) return;
  const normRel = file.rel.replace(/\\/g, "/");
  for (const { spec, offset } of importedSpecs) {
    const basePkg = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : (spec.split("/")[0] ?? spec);
    if (forbidNew.some((f) => spec === f || basePkg === f || spec.startsWith(`${f}/`))) {
      const line = lineOf(file.content, offset);
      findings.push({
        id: `BSL:forbid:${file.rel}:${line}`, rule: "backsliding-forbidden-import", category: "oracle-lock", rung: "R0",
        severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
        message: `Import '${spec}' is blocked by .vstack.json forbidNewImports backsliding lock.`,
        fix: `Replace '${spec}' with the approved paved-path module.`,
      });
    }
    for (const rule of retiring) {
      const matchesMod = spec === rule.module || basePkg === rule.module || spec.startsWith(`${rule.module}/`);
      if (!matchesMod) continue;
      const allowed = rule.allowedImporters?.some((pat) => globMatchesPath(pat, normRel));
      if (allowed) continue;
      const line = lineOf(file.content, offset);
      findings.push({
        id: `BSL:retiring:${file.rel}:${line}`, rule: "backsliding-forbidden-import", category: "oracle-lock", rung: "R0",
        severity: "error", soundness: "incorrectness-witness", file: file.rel, line,
        message: `New import of retiring module '${spec}' outside allowedImporters list.`,
        fix: rule.replacement ? `Use '${rule.replacement}' instead of retiring '${rule.module}'.` : `Migrate off retiring module '${rule.module}'.`,
      });
    }
  }
  const basePkgs = new Set(importedSpecs.map(({ spec }) => (spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : (spec.split("/")[0] ?? spec))));
  for (const group of PAVED_PATH_GROUPS) {
    const hits = group.libs.filter((lib) => basePkgs.has(lib));
    if (hits.length >= 2) {
      findings.push({
        id: `UNC:competing:${file.rel}:${group.concern}`, rule: "competing-paved-paths", category: "structure", rung: "R1",
        severity: "warn", soundness: "hygiene-lint", file: file.rel, line: 1,
        message: `Module mixes competing ${group.concern} libraries (${hits.join(", ")}) in the same file.`,
        fix: `Standardize on a single paved-path ${group.concern} library and lock the retiring one in .vstack.json.`,
      });
    }
  }
}

export function analyzeErrorAndContractGuards(repo: DiscoveredRepo): Finding[] {
  if (!repo.root) throw new Error("repo.root is required.");
  const findings: Finding[] = [];
  const cfg = loadRepoConfig(repo.root);
  const retiring = cfg.retiring ?? [];
  const forbidNew = cfg.forbidNewImports ?? [];
  for (const file of repo.files) {
    if (!file.language || file.isTest || file.isStub) continue;
    const masked = maskCode(file.content, file.language, true);
    checkAspiratorErrorPaths(file, masked, findings);
    checkIoInsideDbTransaction(file, masked, findings);
    checkParseDontValidateAndGuards(file, masked, findings);
    checkImportsBackslidingAndCompeting(file, retiring, forbidNew, findings);
  }
  return findings;
}
