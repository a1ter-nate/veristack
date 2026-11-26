import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseSync } from "oxc-parser";
import { isTestFilePath } from "../discover.ts";
import { maskCode } from "../test-lexical.ts";
import type { PlantedFaultReport, PlantedFaultSurvivor } from "../types.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "./command-audit.ts";
import { parseRunnerTestCounts, stripAnsi } from "./runner-metrics.ts";

interface MutantCandidate {
  file: string;
  line: number;
  start: number;
  end: number;
  replacement: string;
  operator: string;
  original: string;
  mutated: string;
}

const BINARY_MUTATIONS: Record<string, string> = {
  "===": "!==", "!==": "===", "==": "!=", "!=": "==",
  ">=": "<", ">": "<=", "<=": ">", "<": ">=",
};
const LOGICAL_MUTATIONS: Record<string, string> = { "&&": "||", "||": "&&" };

const COMPILE_OR_RUNTIME_CRASH =
  /(?:SyntaxError:\s*(?:Unexpected|invalid\s+syntax|Parse\s+error)|IndentationError:|NameError:|ImportError:|Cannot\s+find\s+module|\bTS\d{4}:|\bCS\d{4}:|error\[E\d{4}\]|cannot\s+find\s+package|syntax\s+error:|undefined:\s+\w+|compilation\s+failed|build\s+failed)/i;

const STRICT_TEST_FAILURE =
  /(?:\b[1-9]\d*\s+fail(?:ed|ure|ures)?\b|AssertionError|AssertionFailed|Expected\s+values|assertion\s+`?left|test\s+result:\s*FAILED|---\s+FAIL:|^FAIL\s+\S|Failed!\s+-|Failed:\s*[1-9]\d*|not\s+ok\s+\d+|✗|×)/m;

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) if (source.charCodeAt(i) === 10) line += 1;
  return line;
}

function maskCommentsOnly(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:\\])\/\/[^\n]*/g, (m) => m.replace(/[^\n]/g, " "));
}

function seededShuffle<T>(items: readonly T[], seed: number): T[] {
  const copy = [...items];
  let state = seed >>> 0;
  for (let i = copy.length - 1; i > 0; i--) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const j = state % (i + 1);
    const tmp = copy[i]; const other = copy[j];
    if (tmp !== undefined && other !== undefined) { copy[i] = other; copy[j] = tmp; }
  }
  return copy;
}

function collectAstMutants(rel: string, source: string, maxPerFile: number, runSeed: number): MutantCandidate[] {
  const all: MutantCandidate[] = [];
  if (!/\.[cm]?[jt]sx?$/.test(rel)) return all;
  let parsed: ReturnType<typeof parseSync>;
  try { parsed = parseSync(rel, source); } catch { return all; }

  const stack: unknown[] = [parsed.program];
  const seenLines = new Set<number>();
  const addCandidate = (c: MutantCandidate): void => {
    if (!seenLines.has(c.line)) { seenLines.add(c.line); all.push(c); }
  };
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    const rec = node as Record<string, unknown>;
    const type = rec.type;
    if (type === "TemplateLiteral") continue;
    if ((type === "IfStatement" || type === "ConditionalExpression") && rec.test && typeof rec.test === "object") {
      const testNode = rec.test as Record<string, unknown>;
      if (typeof testNode.start === "number" && typeof testNode.end === "number") {
        const origTest = source.slice(testNode.start, testNode.end);
        const rep = `!(${origTest})`;
        addCandidate({
          file: rel, line: lineAt(source, testNode.start), start: testNode.start, end: testNode.end,
          replacement: rep, operator: "cond -> !(cond)",
          original: origTest.slice(0, 60), mutated: rep.slice(0, 60),
        });
      }
      if (rec.consequent) stack.push(rec.consequent);
      if (rec.alternate) stack.push(rec.alternate);
      continue;
    }
    if (type === "WhileStatement" || type === "DoWhileStatement") {
      if (rec.body) stack.push(rec.body);
      continue;
    }
    if (type === "ForStatement") {
      if (rec.body) stack.push(rec.body);
      continue;
    }
    if (type === "BinaryExpression" && typeof rec.operator === "string" && typeof rec.start === "number" && typeof rec.end === "number") {
      const left = rec.left as Record<string, unknown> | undefined;
      const right = rec.right as Record<string, unknown> | undefined;
      const replacement = BINARY_MUTATIONS[rec.operator];
      if (replacement && left && right && typeof left.end === "number" && typeof right.start === "number") {
        const opIdx = maskCommentsOnly(source.slice(left.end, right.start)).indexOf(rec.operator);
        if (opIdx >= 0) {
          const opStart = left.end + opIdx;
          const opEnd = opStart + rec.operator.length;
          addCandidate({
            file: rel, line: lineAt(source, opStart), start: opStart, end: opEnd, replacement,
            operator: `${rec.operator} -> ${replacement}`,
            original: source.slice(rec.start, Math.min(rec.end, rec.start + 60)),
            mutated: `${source.slice(rec.start, opStart)}${replacement}${source.slice(opEnd, Math.min(rec.end, opEnd + 30))}`,
          });
        }
      }
    } else if (type === "ReturnStatement") {
      const arg = rec.argument as Record<string, unknown> | undefined;
      if (arg && arg.type === "Literal" && typeof arg.value === "boolean" && typeof arg.start === "number" && typeof arg.end === "number") {
        const origBool = arg.value ? "true" : "false";
        const nextBool = arg.value ? "false" : "true";
        addCandidate({
          file: rel, line: lineAt(source, arg.start), start: arg.start, end: arg.end, replacement: nextBool,
          operator: `${origBool} -> ${nextBool}`, original: `return ${origBool}`, mutated: `return ${nextBool}`,
        });
      }
    }
    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) for (const item of val) stack.push(item);
      else if (val && typeof val === "object") stack.push(val);
    }
  }
  return seededShuffle(all, runSeed).slice(0, maxPerFile);
}

function langForRel(rel: string): string | undefined {
  if (rel.endsWith(".py")) return "python";
  if (rel.endsWith(".rs")) return "rust";
  if (rel.endsWith(".go")) return "go";
  if (rel.endsWith(".cs")) return "csharp";
  return undefined;
}

function collectFallbackMutants(rel: string, source: string, maxPerFile: number, runSeed: number): MutantCandidate[] {
  const masked = maskCode(source, langForRel(rel), true);
  const all: MutantCandidate[] = [];
  const seenLines = new Set<number>();
  const opRe = rel.endsWith(".py") ? /===|!==|==|!=|>=|<=|<|>|\band\b|\bor\b/g : /===|!==|==|!=|>=|<=|&&|\|\||<|>/g;
  for (const m of masked.matchAll(opRe)) {
    const op = m[0]; const idx = m.index ?? -1;
    if (idx < 0) continue;
    const prevCh = idx > 0 ? (masked[idx - 1] ?? "") : "";
    const nextCh = masked[idx + op.length] ?? "";
    if ((op === "<" || op === ">") && (/[A-Za-z0-9_:]/.test(prevCh) || prevCh === "-" || prevCh === "=" || prevCh === "<" || prevCh === ">" || nextCh === "-" || nextCh === "<" || nextCh === ">")) continue;
    const replacement = op === "and" ? "or" : op === "or" ? "and" : (BINARY_MUTATIONS[op] ?? LOGICAL_MUTATIONS[op]);
    if (!replacement) continue;
    const line = lineAt(source, idx);
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    all.push({ file: rel, line, start: idx, end: idx + op.length, replacement, operator: `${op} -> ${replacement}`, original: op, mutated: replacement });
  }
  return seededShuffle(all, runSeed).slice(0, maxPerFile);
}

function randomLocalIdent(): string {
  const words = ["tmp", "val", "chk", "ref", "slot", "acc", "idx", "flag"];
  const prefix = words[crypto.randomInt(words.length)] ?? "tmp";
  return `${prefix}${crypto.randomBytes(3).toString("hex")}`;
}

function findBalancedParenEnd(masked: string, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < masked.length; i++) {
    if (masked[i] === "(") depth += 1;
    else if (masked[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

function findFnBodyOpenBrace(masked: string, startAfterParams: number, allowInlineStructBrace: boolean): number {
  let angle = 0; let paren = 0;
  for (let i = startAfterParams; i < masked.length; i++) {
    const ch = masked[i] ?? "";
    if (ch === "(") paren += 1;
    else if (ch === ")") paren = Math.max(0, paren - 1);
    else if (ch === "<") angle += 1;
    else if (ch === ">" && masked[i - 1] !== "-") angle = Math.max(0, angle - 1);
    else if (paren === 0 && angle === 0) {
      if (ch === ";") return -1;
      if (ch === "{") {
        if (allowInlineStructBrace) {
          const before = masked.slice(Math.max(startAfterParams, i - 16), i);
          if (/\b(?:interface|struct)\s*$/.test(before)) {
            const close = masked.indexOf("}", i + 1);
            if (close > i) { i = close; continue; }
          }
        }
        return i;
      }
    }
  }
  return -1;
}

function insertSemanticNoOp(rel: string, source: string, variant: number): string {
  const id = randomLocalIdent();
  if (/\.[cm]?[jt]sx?$/.test(rel)) {
    const stmts = [` if (false) {} `, ` const ${id} = 0; void ${id}; `, ` { const ${id} = 1; void ${id}; } `];
    const stmt = stmts[variant % stmts.length] ?? stmts[0] ?? " if (false) {} ";
    try {
      const parsed = parseSync(rel, source);
      const stack: unknown[] = [parsed.program];
      while (stack.length > 0) {
        const node = stack.pop();
        if (!node || typeof node !== "object") continue;
        const rec = node as Record<string, unknown>;
        if ((rec.type === "FunctionDeclaration" || rec.type === "FunctionExpression" || rec.type === "ArrowFunctionExpression") && rec.body && typeof rec.body === "object") {
          const body = rec.body as Record<string, unknown>;
          if (body.type === "BlockStatement" && typeof body.start === "number") {
            const pos = body.start + 1;
            const candidate = `${source.slice(0, pos)}${stmt}${source.slice(pos)}`;
            if (parseSync(rel, candidate).errors.length === 0) return candidate;
          }
        }
        for (const val of Object.values(rec)) {
          if (Array.isArray(val)) for (const item of val) stack.push(item);
          else if (val && typeof val === "object") stack.push(val);
        }
      }
    } catch {
      return `${source}\n${stmt}\n`;
    }
    return `${source}\n${stmt}\n`;
  }
  if (rel.endsWith(".py")) {
    const lines = source.split("\n");
    let i = 0; let inTriple: string | null = null;
    while (i < lines.length) {
      const l = (lines[i] ?? "").trim();
      if (inTriple) { if (l.includes(inTriple)) inTriple = null; i += 1; continue; }
      if (l === "" || l.startsWith("#") || l.startsWith("from __future__ import")) { i += 1; continue; }
      const docStart = /^(?:[rRbBuUfF]{0,2})("""|''')/.exec(l);
      if (docStart?.[1]) {
        const q = docStart[1];
        const rest = l.slice(docStart[0].length);
        if (!rest.includes(q)) inTriple = q;
        i += 1; continue;
      }
      break;
    }
    const stmt = variant % 2 === 0 ? "if False:\n    pass" : `${id} = 0`;
    return [...lines.slice(0, i), stmt, ...lines.slice(i)].join("\n");
  }
  const masked = maskCode(source, langForRel(rel), true);
  if (rel.endsWith(".go")) {
    for (const m of masked.matchAll(/\bfunc\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(/g)) {
      const parenEnd = findBalancedParenEnd(masked, (m.index ?? 0) + m[0].length - 1);
      if (parenEnd < 0) continue;
      const braceIdx = findFnBodyOpenBrace(masked, parenEnd + 1, true);
      if (braceIdx >= 0) {
        const stmt = variant % 2 === 0 ? " if false {} " : ` _ = 0; `;
        return `${source.slice(0, braceIdx + 1)}${stmt}${source.slice(braceIdx + 1)}`;
      }
    }
  } else if (rel.endsWith(".rs")) {
    for (const m of masked.matchAll(/\bfn\s+[A-Za-z_]\w*(?:\s*<[^>]*>)?\s*\(/g)) {
      const parenEnd = findBalancedParenEnd(masked, (m.index ?? 0) + m[0].length - 1);
      if (parenEnd < 0) continue;
      const braceIdx = findFnBodyOpenBrace(masked, parenEnd + 1, false);
      if (braceIdx >= 0) {
        const stmt = variant % 2 === 0 ? " if false {} " : ` let ${id} = (); `;
        return `${source.slice(0, braceIdx + 1)}${stmt}${source.slice(braceIdx + 1)}`;
      }
    }
  } else if (rel.endsWith(".cs")) {
    for (const m of masked.matchAll(/\b(?:public|private|internal|protected)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*[A-Za-z0-9_<>,.\s?]+\s+[A-Za-z_]\w*\s*\(/g)) {
      if (/\b(?:class|record|struct|interface)\b/.test(m[0])) continue;
      const parenEnd = findBalancedParenEnd(masked, (m.index ?? 0) + m[0].length - 1);
      if (parenEnd < 0) continue;
      const braceIdx = findFnBodyOpenBrace(masked, parenEnd + 1, false);
      if (braceIdx >= 0) {
        const stmt = variant % 2 === 0 ? " if (false) {} " : ` var ${id} = 0; _ = ${id}; `;
        return `${source.slice(0, braceIdx + 1)}${stmt}${source.slice(braceIdx + 1)}`;
      }
    }
  }
  return `${source}\n`;
}

export interface CanaryOptions {
  repoRoot: string;
  testCmd: string;
  targets?: readonly string[];
  baseRef?: string;
  maxMutants?: number;
  minKillRate?: number;
}

function resolveTargetFiles(options: CanaryOptions): string[] {
  const absRoot = path.resolve(options.repoRoot);
  const targets = new Set<string>();
  const addSafe = (rel: string): void => {
    const norm = rel.trim().replace(/\\/g, "/");
    if (!norm || isTestFilePath(norm)) return;
    const resolved = path.resolve(absRoot, norm);
    if (resolved !== absRoot && !resolved.startsWith(`${absRoot}${path.sep}`)) return;
    if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) targets.add(norm);
  };
  if (options.targets) for (const rel of options.targets) addSafe(rel);
  const ref = options.baseRef ?? (targets.size === 0 ? "HEAD" : undefined);
  if (ref) {
    const diff = spawnSync("git", ["-C", absRoot, "diff", "--name-only", ref, "--"], { encoding: "utf8" });
    if (diff.status === 0) {
      for (const raw of (diff.stdout ?? "").split(/\r?\n/)) {
        const rel = raw.trim();
        if (rel && /\.(?:[cm]?[jt]sx?|py|rs|go|cs)$/.test(rel)) addSafe(rel);
      }
    }
  }
  return [...targets];
}

function linkNodeModulesIntoSandbox(absRoot: string, sandboxDir: string): void {
  const srcNm = path.join(absRoot, "node_modules");
  const dstNm = path.join(sandboxDir, "node_modules");
  if (!fs.existsSync(srcNm)) return;
  const linkDir = (srcDir: string, dstDir: string): void => {
    fs.mkdirSync(dstDir, { recursive: true });
    for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
      const sPath = path.join(srcDir, entry.name);
      const dPath = path.join(dstDir, entry.name);
      if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) { linkDir(sPath, dPath); continue; }
      if (entry.isSymbolicLink()) {
        try {
          const target = fs.realpathSync(sPath);
          if (target === absRoot || target.startsWith(`${absRoot}${path.sep}`)) {
            fs.symlinkSync(path.join(sandboxDir, path.relative(absRoot, target)), dPath);
            continue;
          }
        } catch { continue; }
      }
      try { fs.symlinkSync(sPath, dPath); } catch { continue; }
    }
  };
  linkDir(srcNm, dstNm);
}

function copyRepoForIsolatedCanary(repoRoot: string): string {
  const absRoot = fs.realpathSync(path.resolve(repoRoot));
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), "t-"));
  const skipTop = new Set([".git", "node_modules", ".venv", "venv", "target"]);
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const src = path.join(absRoot, entry.name);
    const dst = path.join(sandboxDir, entry.name);
    if (skipTop.has(entry.name)) {
      if (entry.name === "node_modules") linkNodeModulesIntoSandbox(absRoot, sandboxDir);
      else if (entry.name === ".venv" || entry.name === "venv") { try { fs.symlinkSync(src, dst); } catch { continue; } }
      continue;
    }
    fs.cpSync(src, dst, { recursive: true, dereference: false });
  }
  return sandboxDir;
}

function withOpaqueTmpEnv<T>(baseEnv: NodeJS.ProcessEnv, sandboxDir: string, fn: (env: NodeJS.ProcessEnv) => T): T {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "t-"));
  const pyPaths = [path.join(sandboxDir, "src"), sandboxDir].filter((p) => fs.existsSync(p));
  if (baseEnv.PYTHONPATH) pyPaths.push(baseEnv.PYTHONPATH);
  const env: NodeJS.ProcessEnv = { ...baseEnv, TMPDIR: tmpDir, TMP: tmpDir, TEMP: tmpDir, PYTHONPATH: pyPaths.join(path.delimiter) };
  try {
    return fn(env);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

export function runPlantedFaultCanary(options: CanaryOptions): PlantedFaultReport {
  const absRoot = path.resolve(options.repoRoot);
  const maxMutants = Math.max(1, options.maxMutants ?? 6);
  const minKillRate = Math.max(0.75, options.minKillRate ?? 0.8);
  const failReport = (total: number, invalid: number): PlantedFaultReport => ({
    totalMutants: total, killedMutants: 0, survivedMutants: total, invalidKills: invalid,
    killRate: 0, minKillRate, passed: false, survivors: [],
  });

  const parsedCmd = parseAndValidateCommandArgv("canary", options.testCmd, absRoot);
  if (parsedCmd.error) return failReport(0, 1);

  const runSeed = crypto.randomBytes(4).readUInt32BE(0);
  const targets = resolveTargetFiles(options);
  const candidates: MutantCandidate[] = [];
  const perFileCap = Math.max(1, Math.ceil(maxMutants / Math.max(1, targets.length)));
  for (const rel of targets) {
    if (candidates.length >= maxMutants) break;
    const source = fs.readFileSync(path.join(absRoot, rel), "utf8");
    const found = /\.[cm]?[jt]sx?$/.test(rel) ? collectAstMutants(rel, source, perFileCap, runSeed) : collectFallbackMutants(rel, source, perFileCap, runSeed);
    for (const c of found) if (candidates.length < maxMutants) candidates.push(c);
  }
  if (candidates.length === 0) return failReport(0, 0);

  const baseEnv = scrubChildEnv();
  const sandboxDir = copyRepoForIsolatedCanary(absRoot);
  try {
    const baselineStart = performance.now();
    const baselineRun = withOpaqueTmpEnv(baseEnv, sandboxDir, (env) => runArgvChain(parsedCmd.steps, sandboxDir, env, 90_000));
    const baselineMs = Math.max(500, Math.round(performance.now() - baselineStart));
    const mutantTimeoutMs = Math.round(Math.max(20_000, Math.min(60_000, baselineMs * 6)));
    if (baselineRun.status !== 0) return failReport(candidates.length, candidates.length);

    const uniqueTargetFiles = [...new Set(candidates.map((c) => c.file))];
    const runNoOpCheck = (variant: number): boolean => {
      const originals = new Map<string, string>();
      try {
        for (const rel of uniqueTargetFiles) {
          const p = path.join(sandboxDir, rel);
          const orig = fs.readFileSync(p, "utf8");
          originals.set(rel, orig);
          fs.writeFileSync(p, insertSemanticNoOp(rel, orig, variant), "utf8");
        }
        return withOpaqueTmpEnv(baseEnv, sandboxDir, (env) => runArgvChain(parsedCmd.steps, sandboxDir, env, 90_000)).status === 0;
      } finally {
        for (const [rel, orig] of originals.entries()) fs.writeFileSync(path.join(sandboxDir, rel), orig, "utf8");
      }
    };

    type Task = { kind: "noop"; variant: number } | { kind: "mutant"; mutant: MutantCandidate };
    const tasks: Task[] = [
      { kind: "noop", variant: 0 },
      ...(candidates.length >= 2 ? [{ kind: "noop" as const, variant: 1 }] : []),
      ...candidates.map((mutant) => ({ kind: "mutant" as const, mutant })),
    ];
    const shuffledTasks = seededShuffle(tasks, runSeed ^ 0x9e3779b9);

    let killed = 0; let invalidKills = 0;
    const survivors: PlantedFaultSurvivor[] = [];

    for (const task of shuffledTasks) {
      if (task.kind === "noop") {
        if (!runNoOpCheck(task.variant)) return failReport(candidates.length, candidates.length);
        continue;
      }
      const mutant = task.mutant;
      const mutantPath = path.join(sandboxDir, mutant.file);
      const originalBytes = fs.readFileSync(mutantPath, "utf8");
      const mutatedSource = `${originalBytes.slice(0, mutant.start)}${mutant.replacement}${originalBytes.slice(mutant.end)}`;
      if (/\.[cm]?[jt]sx?$/.test(mutant.file) && parseSync(mutant.file, mutatedSource).errors.length > 0) {
        invalidKills += 1; continue;
      }
      try {
        fs.writeFileSync(mutantPath, mutatedSource, "utf8");
        const mutStart = performance.now();
        const res = withOpaqueTmpEnv(baseEnv, sandboxDir, (env) => runArgvChain(parsedCmd.steps, sandboxDir, env, mutantTimeoutMs));
        const elapsedMs = performance.now() - mutStart;
        const cleanCombined = stripAnsi(`${res.stdout}\n${res.stderr}`);
        const timedOut = (res.signal === "SIGTERM" || (res.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT") && elapsedMs >= mutantTimeoutMs * 0.8;
        if (timedOut) {
          killed += 1;
        } else if (res.signal === "SIGTERM" || res.error) {
          invalidKills += 1;
        } else if (res.status !== 0) {
          const parsedCounts = parseRunnerTestCounts(cleanCombined, parsedCmd.steps);
          const runnerReportedFail = parsedCounts.matched && parsedCounts.failed > 0;
          const hasCrash = COMPILE_OR_RUNTIME_CRASH.test(cleanCombined);
          const hasTestFail = runnerReportedFail || (!hasCrash && STRICT_TEST_FAILURE.test(cleanCombined));
          if (!hasTestFail) invalidKills += 1;
          else killed += 1;
        } else {
          survivors.push({ file: mutant.file, line: mutant.line, operator: mutant.operator, original: mutant.original, mutated: mutant.mutated });
        }
      } finally {
        fs.writeFileSync(mutantPath, originalBytes, "utf8");
      }
    }

    const killRate = Number((killed / candidates.length).toFixed(4));
    const passed = killed > 0 && invalidKills === 0 && killRate >= minKillRate;
    return { totalMutants: candidates.length, killedMutants: killed, survivedMutants: survivors.length, invalidKills, killRate, minKillRate, passed, survivors };
  } finally {
    fs.rmSync(sandboxDir, { recursive: true, force: true });
  }
}
