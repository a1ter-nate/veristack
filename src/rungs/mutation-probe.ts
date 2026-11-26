import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseSync } from "oxc-parser";
import type { PlantedFaultReport, PlantedFaultSurvivor } from "../types.ts";
import { scrubChildEnv, validateExecutableCommand } from "./command-audit.ts";

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
  "===": "!==",
  "!==": "===",
  "==": "!=",
  "!=": "==",
  ">=": ">",
  ">": ">=",
  "<=": "<",
  "<": "<=",
};

const LOGICAL_MUTATIONS: Record<string, string> = {
  "&&": "||",
  "||": "&&",
};

const COMPILE_OR_RUNTIME_CRASH =
  /(?:SyntaxError:\s*(?:Unexpected|invalid\s+syntax|Parse\s+error)|IndentationError:|NameError:|ImportError:|Cannot\s+find\s+module|\bTS\d{4}:|\bCS\d{4}:|error\[E\d{4}\]|cannot\s+find\s+package|syntax\s+error:|undefined:\s+\w+|expected\s+.+,\s+found\s+)/i;

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function maskCommentsOnly(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:\\])\/\/[^\n]*/g, (m) => m.replace(/[^\n]/g, " "));
}

function maskStringsAndCommentsForFallback(source: string): string {
  const cfgIdx = source.search(/#\[cfg\(test\)\]/);
  const active = cfgIdx >= 0 ? source.slice(0, cfgIdx) : source;
  return active
    .replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/`[\s\S]*?`/g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:\\])\/\/[^\n]*/g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|\s)#[^\n]*/g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/"(?:\\.|[^"\\])*"/g, (m) => `"${" ".repeat(Math.max(0, m.length - 2))}"`)
    .replace(/'(?:\\.|[^'\\])'/g, (m) => `'${" ".repeat(Math.max(0, m.length - 2))}'`);
}

function seededShuffle<T>(items: readonly T[], seed: number): T[] {
  const copy = [...items];
  let state = seed >>> 0;
  for (let i = copy.length - 1; i > 0; i--) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const j = state % (i + 1);
    const tmp = copy[i];
    const other = copy[j];
    if (tmp !== undefined && other !== undefined) {
      copy[i] = other;
      copy[j] = tmp;
    }
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
  try {
    parsed = parseSync(rel, source);
  } catch {
    return all;
  }

  const stack: unknown[] = [parsed.program];
  const seenLines = new Set<number>();

  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    const rec = node as Record<string, unknown>;
    const type = rec.type;

    if (
      (type === "BinaryExpression" || type === "LogicalExpression") &&
      typeof rec.operator === "string" &&
      typeof rec.start === "number" &&
      typeof rec.end === "number"
    ) {
      const left = rec.left as Record<string, unknown> | undefined;
      const right = rec.right as Record<string, unknown> | undefined;
      const replacement = type === "BinaryExpression" ? BINARY_MUTATIONS[rec.operator] : LOGICAL_MUTATIONS[rec.operator];
      if (replacement && left && right && typeof left.end === "number" && typeof right.start === "number") {
        const maskedBetween = maskCommentsOnly(source.slice(left.end, right.start));
        const opIdx = maskedBetween.indexOf(rec.operator);
        if (opIdx >= 0) {
          const opStart = left.end + opIdx;
          const opEnd = opStart + rec.operator.length;
          const line = lineAt(source, opStart);
          if (!seenLines.has(line)) {
            seenLines.add(line);
            all.push({
              file: rel,
              line,
              start: opStart,
              end: opEnd,
              operator: `${rec.operator} -> ${replacement}`,
              original: source.slice(rec.start, Math.min(rec.end, rec.start + 60)),
              mutated: `${source.slice(rec.start, opStart)}${replacement}${source.slice(opEnd, Math.min(rec.end, opEnd + 30))}`,
            });
          }
        }
      }
    } else if (type === "ReturnStatement") {
      const arg = rec.argument as Record<string, unknown> | undefined;
      if (
        arg &&
        arg.type === "Literal" &&
        typeof arg.value === "boolean" &&
        typeof arg.start === "number" &&
        typeof arg.end === "number"
      ) {
        const origBool = arg.value ? "true" : "false";
        const nextBool = arg.value ? "false" : "true";
        const line = lineAt(source, arg.start);
        if (!seenLines.has(line)) {
          seenLines.add(line);
          all.push({
            file: rel,
            line,
            start: arg.start,
            end: arg.end,
            operator: `${origBool} -> ${nextBool}`,
            original: `return ${origBool}`,
            mutated: `return ${nextBool}`,
          });
        }
      }
    }

    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) {
        for (const item of val) stack.push(item);
      } else if (val && typeof val === "object") {
        stack.push(val);
      }
    }
  }

  return seededShuffle(all, computeSeedForFile(rel, source)).slice(0, maxPerFile);
}

function collectFallbackMutants(rel: string, source: string, maxPerFile: number): MutantCandidate[] {
  const masked = maskStringsAndCommentsForFallback(source);
  const all: MutantCandidate[] = [];
  const seenLines = new Set<number>();
  const isPython = rel.endsWith(".py");
  const opRe = isPython
    ? /===|!==|==|!=|>=|<=|<|>|\band\b|\bor\b/g
    : /===|!==|==|!=|>=|<=|&&|\|\||<|>/g;

  for (const m of masked.matchAll(opRe)) {
    const op = m[0];
    const idx = m.index ?? -1;
    if (idx < 0) continue;
    const prevCh = idx > 0 ? (masked[idx - 1] ?? "") : "";
    const nextCh = masked[idx + op.length] ?? "";
    if ((op === "<" || op === ">") && (/[A-Za-z0-9_:]/.test(prevCh) || nextCh === ">" || prevCh === "-" || prevCh === "=")) {
      continue;
    }
    const replacement =
      op === "and" ? "or" : op === "or" ? "and" : (BINARY_MUTATIONS[op] ?? LOGICAL_MUTATIONS[op]);
    if (!replacement) continue;
    const line = lineAt(source, idx);
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    all.push({
      file: rel,
      line,
      start: idx,
      end: idx + op.length,
      operator: `${op} -> ${replacement}`,
      original: op,
      mutated: replacement,
    });
  }
  return seededShuffle(all, computeSeedForFile(rel, source)).slice(0, maxPerFile);
}

function insertInteriorNoOp(rel: string, source: string): string {
  const lines = source.split("\n");
  if (lines.length <= 2) return `\n${source}\n`;
  if (rel.endsWith(".py")) {
    const idx = lines.findIndex((l, i) => i > 0 && /^(?:def |class |async def )/.test(l));
    const insertAt = idx > 0 ? idx : Math.floor(lines.length / 2);
    return [...lines.slice(0, insertAt), "", ...lines.slice(insertAt)].join("\n");
  }
  const mid = Math.max(1, Math.floor(lines.length / 2));
  return [...lines.slice(0, mid), "", ...lines.slice(mid)].join("\n");
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
  if (options.targets) {
    for (const rel of options.targets) {
      if (fs.existsSync(path.join(absRoot, rel))) targets.add(rel);
    }
  }
  const ref = options.baseRef ?? (targets.size === 0 ? "HEAD" : undefined);
  if (ref) {
    const diff = spawnSync("git", ["-C", absRoot, "diff", "--name-only", ref, "--"], { encoding: "utf8" });
    if (diff.status === 0) {
      for (const raw of (diff.stdout ?? "").split(/\r?\n/)) {
        const rel = raw.trim();
        if (
          rel &&
          !/(?:test|spec)/i.test(rel) &&
          /\.(?:[cm]?[jt]sx?|py|rs|go|cs)$/.test(rel) &&
          fs.existsSync(path.join(absRoot, rel))
        ) {
          targets.add(rel);
        }
      }
    }
  }
  return [...targets];
}

function copyRepoForIsolatedCanary(repoRoot: string): string {
  const absRoot = path.resolve(repoRoot);
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-canary-"));
  const skipTop = new Set([".git", "node_modules", ".venv", "venv", "target"]);
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    const src = path.join(absRoot, entry.name);
    const dst = path.join(sandboxDir, entry.name);
    if (entry.name === ".git") continue;
    if (skipTop.has(entry.name)) {
      if (entry.name === "node_modules" || entry.name === ".venv" || entry.name === "venv") {
        try {
          fs.symlinkSync(src, dst);
        } catch {
          continue;
        }
      }
      continue;
    }
    fs.cpSync(src, dst, { recursive: true, dereference: false });
  }
  return sandboxDir;
}

export function runPlantedFaultCanary(options: CanaryOptions): PlantedFaultReport {
  const absRoot = path.resolve(options.repoRoot);
  const maxMutants = Math.max(1, options.maxMutants ?? 6);
  const minKillRate = Math.max(0.75, options.minKillRate ?? 0.8);

  if (validateExecutableCommand("canary", options.testCmd, absRoot) !== null) {
    return {
      totalMutants: 0,
      killedMutants: 0,
      survivedMutants: 0,
      invalidKills: 1,
      killRate: 0,
      minKillRate,
      passed: false,
      survivors: [],
    };
  }

  const targets = resolveTargetFiles(options);
  const candidates: MutantCandidate[] = [];
  const perFileCap = Math.max(1, Math.ceil(maxMutants / Math.max(1, targets.length)));

  for (const rel of targets) {
    if (candidates.length >= maxMutants) break;
    const absPath = path.join(absRoot, rel);
    const source = fs.readFileSync(absPath, "utf8");
    const found = /\.[cm]?[jt]sx?$/.test(rel)
      ? collectAstMutants(rel, source, perFileCap)
      : collectFallbackMutants(rel, source, perFileCap);
    for (const c of found) {
      if (candidates.length < maxMutants) candidates.push(c);
    }
  }

  if (candidates.length === 0) {
    return {
      totalMutants: 0,
      killedMutants: 0,
      survivedMutants: 0,
      invalidKills: 0,
      killRate: 0,
      minKillRate,
      passed: false,
      survivors: [],
    };
  }

  const childEnv = scrubChildEnv();
  const sandboxDir = copyRepoForIsolatedCanary(absRoot);
  try {
    const baselineStart = performance.now();
    const baselineRun = spawnSync(options.testCmd, [], {
      cwd: sandboxDir,
      shell: true,
      env: childEnv,
      encoding: "utf8",
      timeout: 90_000,
    });
    const baselineMs = Math.max(500, Math.round(performance.now() - baselineStart));
    const mutantTimeoutMs = Math.round(Math.max(10_000, Math.min(45_000, baselineMs * 8)));
    if (baselineRun.status !== 0) {
      return {
        totalMutants: candidates.length,
        killedMutants: 0,
        survivedMutants: candidates.length,
        invalidKills: candidates.length,
        killRate: 0,
        minKillRate,
        passed: false,
        survivors: [],
      };
    }

    const uniqueTargetFiles = [...new Set(candidates.map((c) => c.file))];
    const originals = new Map<string, string>();
    try {
      for (const rel of uniqueTargetFiles) {
        const noOpPath = path.join(sandboxDir, rel);
        const orig = fs.readFileSync(noOpPath, "utf8");
        originals.set(rel, orig);
        fs.writeFileSync(noOpPath, insertInteriorNoOp(rel, orig), "utf8");
      }
      const noOpRun = spawnSync(options.testCmd, [], {
        cwd: sandboxDir,
        shell: true,
        env: childEnv,
        encoding: "utf8",
        timeout: mutantTimeoutMs,
      });
      if (noOpRun.status !== 0) {
        return {
          totalMutants: candidates.length,
          killedMutants: 0,
          survivedMutants: candidates.length,
          invalidKills: candidates.length,
          killRate: 0,
          minKillRate,
          passed: false,
          survivors: [],
        };
      }
    } finally {
      for (const [rel, orig] of originals.entries()) {
        fs.writeFileSync(path.join(sandboxDir, rel), orig, "utf8");
      }
    }

    let killed = 0;
    let invalidKills = 0;
    const survivors: PlantedFaultSurvivor[] = [];

    for (const mutant of candidates) {
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
        const res = spawnSync(options.testCmd, [], {
          cwd: sandboxDir,
          shell: true,
          env: childEnv,
          encoding: "utf8",
          timeout: mutantTimeoutMs,
        });
        const elapsedMs = performance.now() - mutStart;
        const combined = `${res.stdout ?? ""}\n${res.stderr ?? ""}`;
        const timedOut =
          (res.signal === "SIGTERM" || (res.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT") &&
          elapsedMs >= mutantTimeoutMs * 0.8;
        if (timedOut) {
          killed += 1;
        } else if (res.signal === "SIGTERM" || res.error) {
          invalidKills += 1;
        } else if (res.status !== 0) {
          if (COMPILE_OR_RUNTIME_CRASH.test(combined)) {
            invalidKills += 1;
          } else {
            killed += 1;
          }
        } else {
          survivors.push({
            file: mutant.file,
            line: mutant.line,
            operator: mutant.operator,
            original: mutant.original,
            mutated: mutant.mutated,
          });
        }
      } finally {
        fs.writeFileSync(mutantPath, originalBytes, "utf8");
      }
    }

    const killRate = Number((killed / candidates.length).toFixed(4));
    const passed = killed > 0 && invalidKills === 0 && killRate >= minKillRate;

    return {
      totalMutants: candidates.length,
      killedMutants: killed,
      survivedMutants: survivors.length,
      invalidKills,
      killRate,
      minKillRate,
      passed,
      survivors,
    };
  } finally {
    fs.rmSync(sandboxDir, { recursive: true, force: true });
  }
}
