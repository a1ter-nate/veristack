import { parseSync } from "oxc-parser";
import type { ScannedFile } from "@veristack/plugin";
import type { Finding } from "@veristack/plugin";
import { hasSafetyDirective, lineAtOffset, maskTigerCode, pushTigerFinding, resolveTigerLang } from "@veristack/plugin-tigerstyle";

const EFFECT_IMPORT_RE = /^\s*import\b[^\n]*\bfrom\s+["'](?:effect(?:\/[^"']*)?|@effect\/[^"']*)["']/m;
const UNCAPPED_SCHEDULE_RE = /\bSchedule\.(?:forever|exponential|spaced|fibonacci)\b/;
const SCHEDULE_CAP_RE = /\b(?:Schedule\.(?:recurs|upTo|whileOutput|whileInput|intersect)|Effect\.timeout(?:Fail|Option)?)\b/;
const INVARIANT_ERR_RE = /\b(?:InvariantError|AssertionError|UnreachableError|BugError|IllegalStateError)\b/;

function isEffectFile(file: ScannedFile): boolean {
  if (file.language !== "typescript" && file.language !== "javascript") return false;
  const noComments = file.content.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:\\])\/\/[^\n]*/g, "$1 ");
  return EFFECT_IMPORT_RE.test(noComments);
}

function getCalleePath(callee: unknown): string {
  const parts: string[] = [];
  let cur: unknown = callee;
  for (let depth = 0; depth < 16 && cur && typeof cur === "object"; depth++) {
    const rec = cur as Record<string, unknown>;
    if (rec.type === "Identifier" && typeof rec.name === "string") {
      parts.push(rec.name);
      return parts.reverse().join(".");
    }
    if (rec.type === "MemberExpression") {
      const prop = rec.property as Record<string, unknown> | undefined;
      if (!prop || typeof prop.name !== "string") return "";
      parts.push(prop.name);
      cur = rec.object;
      continue;
    }
    return "";
  }
  return "";
}

function hasExplicitBoundedConcurrency(args: readonly unknown[], source: string): "ok" | "missing" | "unbounded" {
  for (const arg of args) {
    if (!arg || typeof arg !== "object") continue;
    const rec = arg as Record<string, unknown>;
    if (typeof rec.start !== "number" || typeof rec.end !== "number") continue;
    const text = source.slice(rec.start, rec.end);
    if (!/\bconcurrency\s*:/.test(text)) continue;
    if (/\bconcurrency\s*:\s*["']unbounded["']/.test(text)) return "unbounded";
    return "ok";
  }
  return "missing";
}

interface EffectScanCtx {
  file: ScannedFile;
  lines: readonly string[];
  findings: Finding[];
}

function checkEffectConcurrency(
  ctx: EffectScanCtx,
  calleeName: string,
  node: Record<string, unknown>,
): void {
  if (calleeName !== "Effect.forEach" && calleeName !== "Effect.all") return;
  const args = Array.isArray(node.arguments) ? node.arguments : [];
  if (args.length === 0) return;
  const firstArg = args[0] as Record<string, unknown> | undefined;
  if (calleeName === "Effect.all" && (firstArg?.type === "ArrayExpression" || firstArg?.type === "ObjectExpression")) {
    const elements = Array.isArray(firstArg.elements) ? firstArg.elements.length : Array.isArray(firstArg.properties) ? firstArg.properties.length : 0;
    if (elements <= 4) return;
  }
  const ln = lineAtOffset(ctx.file.content, typeof node.start === "number" ? node.start : 0);
  if (hasSafetyDirective(ctx.lines, ln)) return;
  const concStatus = hasExplicitBoundedConcurrency(args, ctx.file.content);
  if (concStatus === "ok") return;
  pushTigerFinding(ctx.findings, {
    rule: "effect-unbounded-concurrency",
    rung: "R0",
    severity: "error",
    file: ctx.file.rel,
    line: ln,
    message: concStatus === "unbounded"
      ? `${calleeName} explicitly sets concurrency: "unbounded", violating TigerStyle upper bounds.`
      : `${calleeName} omits explicit { concurrency: N } bound.`,
    fix: `Pass an explicit bounded { concurrency: MAX_CONCURRENCY } option to ${calleeName}.`,
  });
}

function checkEffectRetryAndFail(
  ctx: EffectScanCtx,
  calleeName: string,
  node: Record<string, unknown>,
): void {
  if (!calleeName) return;
  const start = typeof node.start === "number" ? node.start : 0;
  const end = typeof node.end === "number" ? node.end : start;
  const ln = lineAtOffset(ctx.file.content, start);
  if (hasSafetyDirective(ctx.lines, ln)) return;
  const callText = ctx.file.content.slice(start, end);
  if ((calleeName === "Effect.retry" || calleeName === "Effect.repeat") && UNCAPPED_SCHEDULE_RE.test(callText)) {
    const contextEnd = Math.min(ctx.file.content.length, end + 160);
    const contextSlice = ctx.file.content.slice(Math.max(0, start - 160), contextEnd);
    if (!SCHEDULE_CAP_RE.test(contextSlice)) {
      pushTigerFinding(ctx.findings, {
        rule: "effect-uncapped-retry-schedule",
        rung: "R0",
        severity: "error",
        file: ctx.file.rel,
        line: ln,
        message: `${calleeName} uses an uncapped Schedule without Schedule.recurs, Schedule.upTo, or Effect.timeout.`,
        fix: "Compose the schedule with Schedule.recurs(MAX_RETRIES) or Schedule.upTo(Duration.millis(RETRY_MS_MAX)).",
      });
    }
  }
  if (calleeName === "Effect.fail" && INVARIANT_ERR_RE.test(callText)) {
    pushTigerFinding(ctx.findings, {
      rule: "effect-assertion-as-typed-error",
      rung: "R0",
      severity: "error",
      file: ctx.file.rel,
      line: ln,
      message: "Assertion/invariant failure routed into typed Effect.fail channel instead of a defect.",
      fix: "Halt on programmer invariant violations with Effect.die / Effect.dieMessage / Effect.orDie.",
    });
  }
  if (
    (calleeName === "Effect.catchAll" || calleeName === "Effect.catchAllCause" || calleeName === "Effect.catchAllDefect") &&
    /["'](?:settled|refused|done|closed|completed|cancelled|canceled|rejected|paid|approved)["']/i.test(callText)
  ) {
    pushTigerFinding(ctx.findings, {
      rule: "effect-defect-folded-to-terminal",
      rung: "R0",
      severity: "error",
      file: ctx.file.rel,
      line: ln,
      message: `${calleeName} folds unexpected failures/defects into a terminal domain outcome (uncomplect fence).`,
      fix: "Handle only specific expected domain errors with Effect.catchTag and let unexpected defects propagate or stay pending.",
    });
  }
}

function checkEffectHandlerAllocAndService(file: ScannedFile, lines: readonly string[], findings: Finding[]): void {
  if (!file.content) return;
  const masked = maskTigerCode(file.content, "typescript");
  for (const m of masked.matchAll(/\b(?:HttpRouter|HttpApiBuilder|Effect\.forEach)\b[\s\S]{0,300}\b(?:ManagedRuntime\.make|Layer\.build|Queue\.bounded)\s*\(/g)) {
    const ln = lineAtOffset(file.content, m.index ?? 0);
    if (hasSafetyDirective(lines, ln)) continue;
    pushTigerFinding(findings, {
      rule: "effect-runtime-alloc-in-handler",
      rung: "R1",
      severity: "warn",
      file: file.rel,
      line: ln,
      message: "Allocating Effect ManagedRuntime/Layer/Queue inside a request handler or loop instead of startup Layer wiring.",
      fix: "Construct ManagedRuntime, Layers, and bounded Queues once at application startup and provide via ServiceMap.",
    });
  }
  for (const m of masked.matchAll(/\bServiceMap\.Service\s*<[^>]+>\s*\([^)]*\)\s*\([^,{]*,\s*\{([\s\S]{0,1200}?)\}\s*\)/g)) {
    const body = m[1] ?? "";
    const methodCount = (body.match(/\b[a-zA-Z_]\w*\s*(?::\s*\(|\()/g) ?? []).length;
    if (methodCount > 8) {
      const ln = lineAtOffset(file.content, m.index ?? 0);
      if (hasSafetyDirective(lines, ln)) continue;
      pushTigerFinding(findings, {
        rule: "effect-large-service-interface",
        rung: "R1",
        severity: "warn",
        file: file.rel,
        line: ln,
        message: `Effect v4 ServiceMap.Service exposes ${methodCount} operations (cap: 8).`,
        fix: "Split cohesive capabilities into smaller Effect v4 ServiceMap.Service interfaces.",
      });
    }
  }
  for (const m of masked.matchAll(/\bLayer\.(?:succeed|sync)\s*\(\s*([A-Z]\w*)\s*,\s*(?:\(\s*\)\s*=>\s*)?\{([\s\S]{0,400}?)\}\s*\)/g)) {
    const svcName = m[1] ?? "";
    const body = m[2] ?? "";
    const methods = body.match(/\b[a-zA-Z_]\w*\s*:\s*(?:\([^)]*\)\s*=>|async\s*\()/g) ?? [];
    if (methods.length === 1 && !/\byield\*/.test(body) && /\(\s*\.\.\.args\s*\)\s*=>|\(\s*[a-zA-Z_]\w*\s*\)\s*=>\s*[a-zA-Z_]\w*\.[a-zA-Z_]\w*\s*\(/.test(body)) {
      const ln = lineAtOffset(file.content, m.index ?? 0);
      if (hasSafetyDirective(lines, ln)) continue;
      pushTigerFinding(findings, {
        rule: "effect-passthrough-service-wrapper",
        rung: "R1",
        severity: "warn",
        file: file.rel,
        line: ln,
        message: `Zero-value pass-through Layer wrapper for '${svcName}' forwards 1:1 with zero hidden dependencies (uncomplect fence).`,
        fix: "Delete the pass-through wrapper and call the underlying module directly unless multiple implementations or test doubles exist.",
      });
    }
  }
}

export function analyzeEffectV4Rules(file: ScannedFile): Finding[] {
  if (!resolveTigerLang(file) || !isEffectFile(file)) return [];
  let parsed: ReturnType<typeof parseSync>;
  try { parsed = parseSync(file.rel, file.content); } catch { return []; }
  const findings: Finding[] = [];
  const lines = file.content.split(/\r?\n/);
  const ctx: EffectScanCtx = { file, lines, findings };
  const stack: unknown[] = [parsed.program];
  let visited = 0;
  while (stack.length > 0 && visited < 60_000) {
    visited += 1;
    const cur = stack.pop();
    if (!cur || typeof cur !== "object") continue;
    const rec = cur as Record<string, unknown>;
    if (rec.type === "CallExpression") {
      const calleeName = getCalleePath(rec.callee);
      checkEffectConcurrency(ctx, calleeName, rec);
      checkEffectRetryAndFail(ctx, calleeName, rec);
    }
    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) for (const item of val) stack.push(item);
      else if (val && typeof val === "object") stack.push(val);
    }
  }
  checkEffectHandlerAllocAndService(file, lines, findings);
  return findings;
}
