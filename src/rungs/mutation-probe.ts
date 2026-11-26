import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parseSync } from "oxc-parser";
import type { PlantedFaultReport, PlantedFaultSurvivor } from "../types.ts";

interface MutantCandidate {
  file: string;
  absPath: string;
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
  /\b(?:SyntaxError|ReferenceError|TypeError:\s*Cannot\s+find|Cannot\s+find\s+module|TS\d{4}:|error\[E\d{4}\]|IndentationError|ImportError)\b/;

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function collectAstMutants(rel: string, absPath: string, source: string, maxPerFile: number): MutantCandidate[] {
  const out: MutantCandidate[] = [];
  if (!/\.[cm]?[jt]sx?$/.test(rel)) return out;
  let parsed: ReturnType<typeof parseSync>;
  try {
    parsed = parseSync(rel, source);
  } catch {
    return out;
  }

  const stack: unknown[] = [parsed.program];
  const seenLines = new Set<number>();

  while (stack.length > 0 && out.length < maxPerFile) {
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
        const between = source.slice(left.end, right.start);
        const opIdx = between.indexOf(rec.operator);
        if (opIdx >= 0) {
          const opStart = left.end + opIdx;
          const opEnd = opStart + rec.operator.length;
          const line = lineAt(source, opStart);
          if (!seenLines.has(line)) {
            seenLines.add(line);
            out.push({
              file: rel,
              absPath,
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
    }

    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) {
        for (let i = val.length - 1; i >= 0; i--) stack.push(val[i]);
      } else if (val && typeof val === "object" && "type" in val) {
        stack.push(val);
      }
    }
  }
  return out;
}

function collectFallbackMutants(rel: string, absPath: string, source: string, maxPerFile: number): MutantCandidate[] {
  const out: MutantCandidate[] = [];
  const re = /(===|!==|>=|<=|==|!=|&&|\|\|)/g;
  const seenLines = new Set<number>();
  for (const m of source.matchAll(re)) {
    if (out.length >= maxPerFile) break;
    const op = m[1] ?? "";
    const idx = m.index ?? -1;
    if (idx < 0) continue;
    const replacement = BINARY_MUTATIONS[op] ?? LOGICAL_MUTATIONS[op];
    if (!replacement) continue;
    const line = lineAt(source, idx);
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    out.push({
      file: rel,
      absPath,
      line,
      start: idx,
      end: idx + op.length,
      operator: `${op} -> ${replacement}`,
      original: op,
      mutated: replacement,
    });
  }
  return out;
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
  if (options.targets && options.targets.length > 0) {
    return options.targets.filter((rel) => fs.existsSync(path.join(options.repoRoot, rel)));
  }
  if (options.baseRef) {
    const diff = spawnSync("git", ["-C", options.repoRoot, "diff", "--name-only", options.baseRef, "--"], {
      encoding: "utf8",
    });
    if (diff.status === 0) {
      const changed = (diff.stdout ?? "")
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s && !/(?:test|spec)/i.test(s) && /\.(?:[cm]?[jt]sx?|py|rs|go|cs)$/.test(s))
        .filter((s) => fs.existsSync(path.join(options.repoRoot, s)));
      if (changed.length > 0) return changed;
    }
  }
  return [];
}

export function runPlantedFaultCanary(options: CanaryOptions): PlantedFaultReport {
  const maxMutants = options.maxMutants ?? 6;
  const minKillRate = options.minKillRate ?? 0.8;
  const targets = resolveTargetFiles(options);
  const candidates: MutantCandidate[] = [];
  const perFileCap = Math.max(1, Math.ceil(maxMutants / Math.max(1, targets.length)));

  for (const rel of targets) {
    if (candidates.length >= maxMutants) break;
    const absPath = path.join(options.repoRoot, rel);
    const source = fs.readFileSync(absPath, "utf8");
    const found = /\.[cm]?[jt]sx?$/.test(rel)
      ? collectAstMutants(rel, absPath, source, perFileCap)
      : collectFallbackMutants(rel, absPath, source, perFileCap);
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

  const baselineRun = spawnSync(options.testCmd, [], {
    cwd: options.repoRoot,
    shell: true,
    encoding: "utf8",
    timeout: 90_000,
  });
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

  let killed = 0;
  let invalidKills = 0;
  const survivors: PlantedFaultSurvivor[] = [];

  for (const mutant of candidates) {
    const originalBytes = fs.readFileSync(mutant.absPath, "utf8");
    const replacementOp = mutant.operator.split(" -> ")[1] ?? mutant.mutated;
    const mutatedSource = `${originalBytes.slice(0, mutant.start)}${replacementOp}${originalBytes.slice(mutant.end)}`;

    try {
      fs.writeFileSync(mutant.absPath, mutatedSource, "utf8");
      const res = spawnSync(options.testCmd, [], {
        cwd: options.repoRoot,
        shell: true,
        encoding: "utf8",
        timeout: 45_000,
      });
      const combined = `${res.stdout ?? ""}\n${res.stderr ?? ""}`;
      if (res.signal === "SIGTERM" || res.error) {
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
      fs.writeFileSync(mutant.absPath, originalBytes, "utf8");
    }
  }

  const effectiveTotal = Math.max(1, candidates.length - invalidKills);
  const killRate = Number((killed / effectiveTotal).toFixed(4));
  const passed = killed > 0 && killRate >= minKillRate;

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
}
