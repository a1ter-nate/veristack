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

interface MutantCandidate {
  file: string;
  line: number;
  start: number;
  end: number;
  operator: string;
  original: string;
  mutated: string;
}

const BINARY_MUTATIONS: Record<string, string> = {
  "===": "!==", "!==": "===", "==": "!=", "!=": "==",
  ">=": ">", ">": ">=", "<=": "<", "<": "<=",
};
const LOGICAL_MUTATIONS: Record<string, string> = { "&&": "||", "||": "&&" };

const COMPILE_OR_RUNTIME_CRASH =
  /(?:SyntaxError:\s*(?:Unexpected|invalid\s+syntax|Parse\s+error)|IndentationError:|NameError:|ImportError:|Cannot\s+find\s+module|\bTS\d{4}:|\bCS\d{4}:|error\[E\d{4}\]|cannot\s+find\s+package|syntax\s+error:|undefined:\s+\w+)/i;

const TEST_FAILURE_EVIDENCE =
  /(?:\b[1-9]\d*\s+fail(?:ed|ure|ures)?\b|\bFAIL\b|\bFAILED\b|AssertionError|AssertionFailed|Expected\s+values|assertion\s+`?left|assert\s+failed|test\s+result:\s*FAILED|Failed:\s*[1-9]\d*|not\s+ok\s+\d+|✗|×)/i;

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
    const tmp = copy[i];
    const other = copy[j];
    if (tmp !== undefined && other !== undefined) { copy[i] = other; copy[j] = tmp; }
  }
  return copy;
}

function computeSeedForFile(rel: string, source: string): number {
  const seedStr = `${rel}\0${source}`;
  let h = 2166136261;
  for (let i = 0; i < seedStr.length; i++) {
    h ^= seedStr.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function collectAstMutants(rel: string, source: string, maxPerFile: number): MutantCandidate[] {
  const all: MutantCandidate[] = [];
  if (!/\.[cm]?[jt]sx?$/.test(rel)) return all;
  let parsed: ReturnType<typeof parseSync>;
  try { parsed = parseSync(rel, source); } catch { return all; }

  const stack: unknown[] = [parsed.program];
  const seenLines = new Set<number>();

  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    const rec = node as Record<string, unknown>;
    const type = rec.type;

    if ((type === "BinaryExpression" || type === "LogicalExpression") && typeof rec.operator === "string" && typeof rec.start === "number" && typeof rec.end === "number") {
      const left = rec.left as Record<string, unknown> | undefined;
      const right = rec.right as Record<string, unknown> | undefined;
      const replacement = type === "BinaryExpression" ? BINARY_MUTATIONS[rec.operator] : LOGICAL_MUTATIONS[rec.operator];
      if (replacement && left && right && typeof left.end === "number" && typeof right.start === "number") {
        const opIdx = maskCommentsOnly(source.slice(left.end, right.start)).indexOf(rec.operator);
        if (opIdx >= 0) {
          const opStart = left.end + opIdx;
          const opEnd = opStart + rec.operator.length;
          const line = lineAt(source, opStart);
          if (!seenLines.has(line)) {
            seenLines.add(line);
            all.push({
              file: rel, line, start: opStart, end: opEnd,
              operator: `${rec.operator} -> ${replacement}`,
              original: source.slice(rec.start, Math.min(rec.end, rec.start + 60)),
              mutated: `${source.slice(rec.start, opStart)}${replacement}${source.slice(opEnd, Math.min(rec.end, opEnd + 30))}`,
            });
          }
        }
      }
    } else if (type === "ReturnStatement") {
      const arg = rec.argument as Record<string, unknown> | undefined;
      if (arg && arg.type === "Literal" && typeof arg.value === "boolean" && typeof arg.start === "number" && typeof arg.end === "number") {
        const origBool = arg.value ? "true" : "false";
        const nextBool = arg.value ? "false" : "true";
        const line = lineAt(source, arg.start);
        if (!seenLines.has(line)) {
          seenLines.add(line);
          all.push({ file: rel, line, start: arg.start, end: arg.end, operator: `${origBool} -> ${nextBool}`, original: `return ${origBool}`, mutated: `return ${nextBool}` });
        }
      }
    }

    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) for (const item of val) stack.push(item);
      else if (val && typeof val === "object") stack.push(val);
    }
  }
  return seededShuffle(all, computeSeedForFile(rel, source)).slice(0, maxPerFile);
}

function langForRel(rel: string): string | undefined {
  if (rel.endsWith(".py")) return "python";
  if (rel.endsWith(".rs")) return "rust";
  if (rel.endsWith(".go")) return "go";
  if (rel.endsWith(".cs")) return "csharp";
  return undefined;
}

function collectFallbackMutants(rel: string, source: string, maxPerFile: number): MutantCandidate[] {
  const masked = maskCode(source, langForRel(rel), true);
  const all: MutantCandidate[] = [];
  const seenLines = new Set<number>();
  const opRe = rel.endsWith(".py") ? /===|!==|==|!=|>=|<=|<|>|\band\b|\bor\b/g : /===|!==|==|!=|>=|<=|&&|\|\||<|>/g;

  for (const m of masked.matchAll(opRe)) {
    const op = m[0];
    const idx = m.index ?? -1;
    if (idx < 0) continue;
    const prevCh = idx > 0 ? (masked[idx - 1] ?? "") : "";
    const nextCh = masked[idx + op.length] ?? "";
    if ((op === "<" || op === ">") && (/[A-Za-z0-9_:]/.test(prevCh) || prevCh === "-" || prevCh === "=" || prevCh === "<" || prevCh === ">" || nextCh === "-" || nextCh === "<" || nextCh === ">")) continue;
    const replacement = op === "and" ? "or" : op === "or" ? "and" : (BINARY_MUTATIONS[op] ?? LOGICAL_MUTATIONS[op]);
    if (!replacement) continue;
    const line = lineAt(source, idx);
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    all.push({ file: rel, line, start: idx, end: idx + op.length, operator: `${op} -> ${replacement}`, original: op, mutated: replacement });
  }
  return seededShuffle(all, computeSeedForFile(rel, source)).slice(0, maxPerFile);
}

function insertSemanticNoOp(rel: string, source: string, nonce: string): string {
  if (/\.[cm]?[jt]sx?$/.test(rel)) {
    const stmt = ` const _v_${nonce} = 0; void _v_${nonce}; `;
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
      return `${source}\nconst _v_${nonce} = 0; void _v_${nonce};\n`;
    }
    return `${source}\nconst _v_${nonce} = 0; void _v_${nonce};\n`;
  }
  if (rel.endsWith(".py")) {
    const lines = source.split("\n");
    let insertAt = 0;
    while (insertAt < lines.length) {
      const l = (lines[insertAt] ?? "").trim();
      if (l === "" || l.startsWith("#") || l.startsWith("from __future__ import")) { insertAt += 1; continue; }
      if (insertAt <= 2 && (/^"""[\s\S]*"""$/.test(l) || /^'''[\s\S]*'''$/.test(l))) { insertAt += 1; continue; }
      break;
    }
    return [...lines.slice(0, insertAt), `_v_${nonce} = 0`, ...lines.slice(insertAt)].join("\n");
  }
  const masked = maskCode(source, langForRel(rel), true);
  const fnMatch = rel.endsWith(".rs")
    ? /\bfn\s+\w+[^{]*\{/.exec(masked)
    : rel.endsWith(".go")
      ? /\bfunc\s+(?:\([^)]*\)\s*)?\w+[^{]*\{/.exec(masked)
      : /\)\s*\{/.exec(masked);
  if (fnMatch && fnMatch.index !== undefined) {
    const bracePos = fnMatch.index + fnMatch[0].length;
    const stmt = rel.endsWith(".rs") ? ` let _v_${nonce} = (); ` : rel.endsWith(".go") ? ` _ = 0; ` : ` var _v_${nonce} = 0; _ = _v_${nonce}; `;
    return `${source.slice(0, bracePos)}${stmt}${source.slice(bracePos)}`;
  }
  return `${source}\n/* vstack-noop-${nonce} */\n`;
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
      if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) {
        linkDir(sPath, dPath);
        continue;
      }
      if (entry.isSymbolicLink()) {
        try {
          const target = fs.realpathSync(sPath);
          if (target === absRoot || target.startsWith(`${absRoot}${path.sep}`)) {
            fs.symlinkSync(path.join(sandboxDir, path.relative(absRoot, target)), dPath);
            continue;
          }
        } catch {
          continue;
        }
      }
      try { fs.symlinkSync(sPath, dPath); } catch { continue; }
    }
  };
  linkDir(srcNm, dstNm);
}

function copyRepoForIsolatedCanary(repoRoot: string): string {
  const absRoot = fs.realpathSync(path.resolve(repoRoot));
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-canary-"));
  const skipTop = new Set([".git", "node_modules", ".venv", "venv", "target"]);
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const src = path.join(absRoot, entry.name);
    const dst = path.join(sandboxDir, entry.name);
    if (skipTop.has(entry.name)) {
      if (entry.name === "node_modules") linkNodeModulesIntoSandbox(absRoot, sandboxDir);
      else if (entry.name === ".venv" || entry.name === "venv") {
        try { fs.symlinkSync(src, dst); } catch { continue; }
      }
      continue;
    }
    fs.cpSync(src, dst, { recursive: true, dereference: false });
  }
  return sandboxDir;
}

function makeIsolatedEnv(baseEnv: NodeJS.ProcessEnv, sandboxDir: string, tag: string): NodeJS.ProcessEnv {
  const tmpDir = path.join(sandboxDir, `.tmp-${tag}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  return { ...baseEnv, TMPDIR: tmpDir, TMP: tmpDir, TEMP: tmpDir };
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

  const targets = resolveTargetFiles(options);
  const candidates: MutantCandidate[] = [];
  const perFileCap = Math.max(1, Math.ceil(maxMutants / Math.max(1, targets.length)));

  for (const rel of targets) {
    if (candidates.length >= maxMutants) break;
    const source = fs.readFileSync(path.join(absRoot, rel), "utf8");
    const found = /\.[cm]?[jt]sx?$/.test(rel) ? collectAstMutants(rel, source, perFileCap) : collectFallbackMutants(rel, source, perFileCap);
    for (const c of found) if (candidates.length < maxMutants) candidates.push(c);
  }
  if (candidates.length === 0) return failReport(0, 0);

  const baseEnv = scrubChildEnv();
  const sandboxDir = copyRepoForIsolatedCanary(absRoot);
  try {
    const baselineStart = performance.now();
    const baselineRun = runArgvChain(parsedCmd.steps, sandboxDir, makeIsolatedEnv(baseEnv, sandboxDir, "base"), 90_000);
    const baselineMs = Math.max(500, Math.round(performance.now() - baselineStart));
    const mutantTimeoutMs = Math.round(Math.max(15_000, Math.min(60_000, baselineMs * 10)));
    if (baselineRun.status !== 0) return failReport(candidates.length, candidates.length);

    const uniqueTargetFiles = [...new Set(candidates.map((c) => c.file))];
    const runNoOpCheck = (tag: string): boolean => {
      const nonce = crypto.randomBytes(4).toString("hex");
      const originals = new Map<string, string>();
      try {
        for (const rel of uniqueTargetFiles) {
          const p = path.join(sandboxDir, rel);
          const orig = fs.readFileSync(p, "utf8");
          originals.set(rel, orig);
          fs.writeFileSync(p, insertSemanticNoOp(rel, orig, nonce), "utf8");
        }
        return runArgvChain(parsedCmd.steps, sandboxDir, makeIsolatedEnv(baseEnv, sandboxDir, tag), mutantTimeoutMs).status === 0;
      } finally {
        for (const [rel, orig] of originals.entries()) fs.writeFileSync(path.join(sandboxDir, rel), orig, "utf8");
      }
    };

    if (!runNoOpCheck("noop-0")) return failReport(candidates.length, candidates.length);

    const midNoOpIdx = Math.floor(candidates.length / 2);
    let killed = 0;
    let invalidKills = 0;
    const survivors: PlantedFaultSurvivor[] = [];

    for (let idx = 0; idx < candidates.length; idx++) {
      if (idx === midNoOpIdx && candidates.length >= 2 && !runNoOpCheck("noop-mid")) {
        return failReport(candidates.length, candidates.length);
      }
      const mutant = candidates[idx];
      if (!mutant) continue;
      const mutantPath = path.join(sandboxDir, mutant.file);
      const originalBytes = fs.readFileSync(mutantPath, "utf8");
      const replacementOp = mutant.operator.split(" -> ")[1] ?? mutant.mutated;
      const mutatedSource = `${originalBytes.slice(0, mutant.start)}${replacementOp}${originalBytes.slice(mutant.end)}`;
      if (/\.[cm]?[jt]sx?$/.test(mutant.file) && parseSync(mutant.file, mutatedSource).errors.length > 0) {
        invalidKills += 1;
        continue;
      }

      try {
        fs.writeFileSync(mutantPath, mutatedSource, "utf8");
        const mutStart = performance.now();
        const res = runArgvChain(parsedCmd.steps, sandboxDir, makeIsolatedEnv(baseEnv, sandboxDir, `m${idx}`), mutantTimeoutMs);
        const elapsedMs = performance.now() - mutStart;
        const combined = `${res.stdout}\n${res.stderr}`;
        const timedOut = (res.signal === "SIGTERM" || (res.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT") && elapsedMs >= mutantTimeoutMs * 0.8;
        if (timedOut) {
          killed += 1;
        } else if (res.signal === "SIGTERM" || res.error) {
          invalidKills += 1;
        } else if (res.status !== 0) {
          const hasTestFail = TEST_FAILURE_EVIDENCE.test(combined);
          if ((COMPILE_OR_RUNTIME_CRASH.test(combined) && !hasTestFail) || !hasTestFail) invalidKills += 1;
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
