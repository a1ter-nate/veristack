import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseSync } from "oxc-parser";
import { isTestFilePath } from "@veristack/plugin";
import { maskCode } from "@veristack/plugin";
import type { PlantedFaultReport, PlantedFaultSurvivor } from "@veristack/plugin";
import { classifyCanaryOutcome, executeCanaryPlanAsync, isRetryableCanarySignal, type AsyncCanaryTask } from "./canary-runner.ts";
import { isAridMutationLine, parseDiffChangedLines } from "./diff-and-shuffle.ts";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "@veristack/plugin-control-plane";
import { runGitClean } from "@veristack/plugin-control-plane";
import { parseRunnerTestCounts, stripAnsi } from "./runner-metrics.ts";

interface MutantCandidate { file: string; line: number; start: number; end: number; replacement: string; operator: string; original: string; mutated: string; }
export interface CanaryOptions { repoRoot: string; testCmd: string; targets?: readonly string[]; baseRef?: string; diffRef?: string; aridFilter?: boolean; maxMutants?: number; minKillRate?: number; concurrency?: number; }

const BINARY_MUTATIONS: Record<string, string> = { "===": "!==", "!==": "===", "==": "!=", "!=": "==", ">=": "<", ">": "<=", "<=": ">", "<": ">=" };
const LOGICAL_MUTATIONS: Record<string, string> = { "&&": "||", "||": "&&" };

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) if (source.charCodeAt(i) === 10) line += 1;
  return line;
}

function maskCommentsOnly(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/(^|[^:\\])\/\/[^\n]*/g, (m) => m.replace(/[^\n]/g, " "));
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

function collectNodeMutant(
  rec: Record<string, unknown>,
  rel: string,
  source: string,
  addCandidate: (c: MutantCandidate) => void,
): void {
  const type = rec.type;
  if (type === "BinaryExpression" || type === "LogicalExpression") {
    const op = typeof rec.operator === "string" ? rec.operator : "";
    const left = rec.left as Record<string, unknown> | undefined;
    const right = rec.right as Record<string, unknown> | undefined;
    const replacement = type === "BinaryExpression" ? BINARY_MUTATIONS[op] : LOGICAL_MUTATIONS[op];
    if (!replacement || !left || !right || typeof left.end !== "number" || typeof right.start !== "number" || typeof rec.start !== "number" || typeof rec.end !== "number") return;
    const opIdx = maskCommentsOnly(source.slice(left.end, right.start)).indexOf(op);
    if (opIdx < 0) return;
    const opStart = left.end + opIdx;
    const opEnd = opStart + op.length;
    addCandidate({
      file: rel, line: lineAt(source, opStart), start: opStart, end: opEnd, replacement, operator: `${op} -> ${replacement}`,
      original: source.slice(rec.start, Math.min(rec.end, rec.start + 60)),
      mutated: `${source.slice(rec.start, opStart)}${replacement}${source.slice(opEnd, Math.min(rec.end, opEnd + 30))}`,
    });
    return;
  }
  if (type === "UnaryExpression" && rec.operator === "!" && typeof rec.start === "number" && typeof rec.end === "number" && rec.argument && typeof rec.argument === "object") {
    const arg = rec.argument as Record<string, unknown>;
    if (typeof arg.start !== "number" || typeof arg.end !== "number") return;
    const inner = source.slice(arg.start, arg.end);
    addCandidate({ file: rel, line: lineAt(source, rec.start), start: rec.start, end: rec.end, replacement: `(${inner})`, operator: "!x -> x", original: source.slice(rec.start, Math.min(rec.end, rec.start + 60)), mutated: `(${inner})`.slice(0, 60) });
    return;
  }
  if (type !== "ReturnStatement") return;
  const arg = rec.argument as Record<string, unknown> | undefined;
  if (arg && arg.type === "Literal" && typeof arg.value === "boolean" && typeof arg.start === "number" && typeof arg.end === "number") {
    const origBool = arg.value ? "true" : "false";
    const nextBool = arg.value ? "false" : "true";
    addCandidate({ file: rel, line: lineAt(source, arg.start), start: arg.start, end: arg.end, replacement: nextBool, operator: `${origBool} -> ${nextBool}`, original: `return ${origBool}`, mutated: `return ${nextBool}` });
  } else if (arg && arg.type === "BinaryExpression" && (arg.operator === "+" || arg.operator === "-") && typeof arg.start === "number" && typeof arg.end === "number") {
    const left = arg.left as Record<string, unknown> | undefined;
    const right = arg.right as Record<string, unknown> | undefined;
    const rep = arg.operator === "+" ? "-" : "+";
    if (!left || !right || typeof left.end !== "number" || typeof right.start !== "number") return;
    const opIdx = maskCommentsOnly(source.slice(left.end, right.start)).indexOf(arg.operator);
    if (opIdx < 0) return;
    const opStart = left.end + opIdx;
    addCandidate({ file: rel, line: lineAt(source, opStart), start: opStart, end: opStart + 1, replacement: rep, operator: `${arg.operator} -> ${rep}`, original: source.slice(arg.start, Math.min(arg.end, arg.start + 60)), mutated: rep });
  }
}

function collectAstMutants(rel: string, source: string, maxPerFile: number, runSeed: number): MutantCandidate[] {
  const all: MutantCandidate[] = [];
  if (!rel) return all;
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
        addCandidate({ file: rel, line: lineAt(source, testNode.start), start: testNode.start, end: testNode.end, replacement: rep, operator: "cond -> !(cond)", original: origTest.slice(0, 60), mutated: rep.slice(0, 60) });
      }
      if (rec.consequent) stack.push(rec.consequent);
      if (rec.alternate) stack.push(rec.alternate);
      continue;
    }
    if (type === "WhileStatement" || type === "DoWhileStatement" || type === "ForStatement") {
      if (rec.body) stack.push(rec.body);
      continue;
    }
    collectNodeMutant(rec, rel, source, addCandidate);
    for (const val of Object.values(rec)) {
      if (Array.isArray(val)) for (const item of val) stack.push(item);
      else if (val && typeof val === "object") stack.push(val);
    }
  }
  return seededShuffle(all, runSeed).slice(0, maxPerFile);
}

function langForRel(rel: string): string | undefined {
  return rel.endsWith(".py") ? "python" : rel.endsWith(".rs") ? "rust" : rel.endsWith(".go") ? "go" : rel.endsWith(".cs") ? "csharp" : undefined;
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
    if ((op === "<" || op === ">") && (/[A-Za-z0-9_:)?>\]]/.test(prevCh) || prevCh === "-" || prevCh === "=" || prevCh === "<" || nextCh === "-" || nextCh === "<" || nextCh === ">" || nextCh === "(")) continue;
    if (rel.endsWith(".rs") && (op === "&&" || op === "||")) {
      const before = masked.slice(Math.max(0, idx - 12), idx).trimEnd();
      if (op === "&&" && (!before || /[(:=,[<]$/.test(before))) continue;
      if (op === "||" && (!before || /[(:=,[{]$|\bmove$/.test(before))) continue;
    }
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
  let angle = 0; let paren = 0; let bracket = 0;
  for (let i = startAfterParams; i < masked.length; i++) {
    const ch = masked[i] ?? "";
    if (ch === "(") { paren += 1; continue; }
    if (ch === ")") { paren = Math.max(0, paren - 1); continue; }
    if (ch === "[") { bracket += 1; continue; }
    if (ch === "]") { bracket = Math.max(0, bracket - 1); continue; }
    if (ch === "<") { angle += 1; continue; }
    if (ch === ">" && masked[i - 1] !== "-") { angle = Math.max(0, angle - 1); continue; }
    if (paren !== 0 || angle !== 0 || bracket !== 0) continue;
    if (ch === ";" || (ch === "=" && masked[i + 1] === ">")) return -1;
    if (ch !== "{") continue;
    if (allowInlineStructBrace && /\b(?:interface|struct)\s*$/.test(masked.slice(Math.max(startAfterParams, i - 16), i))) {
      const close = masked.indexOf("}", i + 1);
      if (close > i) { i = close; continue; }
    }
    return i;
  }
  return -1;
}

function insertJsSemanticNoOp(rel: string, source: string, id: string, variant: number): string {
  const stmt = variant % 2 === 0 ? ` const ${id} = 0; void ${id}; ` : ` if (false) {} `;
  try {
    const parsed = parseSync(rel, source);
    const walkFind = (fn: (rec: Record<string, unknown>) => string | null): string | null => {
      const stack: unknown[] = [parsed.program];
      while (stack.length > 0) {
        const node = stack.pop();
        if (!node || typeof node !== "object") continue;
        const rec = node as Record<string, unknown>;
        const hit = fn(rec);
        if (hit !== null) return hit;
        for (const val of Object.values(rec)) {
          if (Array.isArray(val)) for (const item of val) stack.push(item);
          else if (val && typeof val === "object") stack.push(val);
        }
      }
      return null;
    };
    if (variant % 3 === 1) {
      const wrapped = walkFind((rec) => {
        if (rec.type !== "ReturnStatement" || !rec.argument || typeof rec.argument !== "object") return null;
        const arg = rec.argument as Record<string, unknown>;
        if (typeof arg.start !== "number" || typeof arg.end !== "number") return null;
        const c = `${source.slice(0, arg.start)}(${source.slice(arg.start, arg.end)})${source.slice(arg.end)}`;
        return parseSync(rel, c).errors.length === 0 ? c : null;
      });
      if (wrapped) return wrapped;
    }
    if (variant % 3 === 2) {
      const boolCond = walkFind((rec) => {
        if (rec.type !== "IfStatement" || !rec.test || typeof rec.test !== "object") return null;
        const t = rec.test as Record<string, unknown>;
        if (typeof t.start !== "number" || typeof t.end !== "number") return null;
        const c = `${source.slice(0, t.start)}Boolean(${source.slice(t.start, t.end)})${source.slice(t.end)}`;
        return parseSync(rel, c).errors.length === 0 ? c : null;
      });
      if (boolCond) return boolCond;
    }
    const inFn = walkFind((rec) => {
      if ((rec.type === "FunctionDeclaration" || rec.type === "FunctionExpression" || rec.type === "ArrowFunctionExpression") && rec.body && typeof rec.body === "object") {
        const body = rec.body as Record<string, unknown>;
        if (body.type === "BlockStatement" && typeof body.start === "number") {
          const c = `${source.slice(0, body.start + 1)}${stmt}${source.slice(body.start + 1)}`;
          return parseSync(rel, c).errors.length === 0 ? c : null;
        }
      }
      return null;
    });
    if (inFn) return inFn;
  } catch { return `${source}\n${stmt}\n`; }
  return `${source}\n${stmt}\n`;
}

function insertPySemanticNoOp(source: string, id: string, variant: number): string {
  const lines = source.split("\n");
  let i = 0; let inTriple: string | null = null; let inFutureParen = false; let inFutureBs = false;
  while (i < lines.length) {
    const l = (lines[i] ?? "").trim();
    if (inTriple) { if (l.includes(inTriple)) inTriple = null; i += 1; continue; }
    if (inFutureParen) { if (l.includes(")")) inFutureParen = false; i += 1; continue; }
    if (inFutureBs) { if (!l.endsWith("\\")) inFutureBs = false; i += 1; continue; }
    if (l === "" || l.startsWith("#")) { i += 1; continue; }
    if (l.startsWith("from __future__ import")) {
      if (l.includes("(") && !l.includes(")")) inFutureParen = true;
      else if (l.endsWith("\\")) inFutureBs = true;
      i += 1; continue;
    }
    const ds = /^(?:[rRbBuUfF]{0,2})("""|''')/.exec(l);
    if (ds?.[1]) { if (!l.slice(ds[0].length).includes(ds[1])) inTriple = ds[1]; i += 1; continue; }
    if (/^(?:[rRbBuUfF]{0,2})(?:"[^"\n]*"|'[^'\n]*')$/.test(l)) { i += 1; continue; }
    break;
  }
  return [...lines.slice(0, i), variant % 2 === 0 ? "if False:\n    pass" : `_${id} = 0`, ...lines.slice(i)].join("\n");
}

export function insertSemanticNoOp(rel: string, source: string, variant: number): string {
  const id = randomLocalIdent();
  if (/\.[cm]?[jt]sx?$/.test(rel)) return insertJsSemanticNoOp(rel, source, id, variant);
  if (rel.endsWith(".py")) return insertPySemanticNoOp(source, id, variant);
  const masked = maskCode(source, langForRel(rel), true);
  if (rel.endsWith(".go")) {
    for (const m of masked.matchAll(/\bfunc\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(/g)) {
      const pEnd = findBalancedParenEnd(masked, (m.index ?? 0) + m[0].length - 1);
      const bIdx = pEnd >= 0 ? findFnBodyOpenBrace(masked, pEnd + 1, true) : -1;
      if (bIdx >= 0) return `${source.slice(0, bIdx + 1)}${variant % 2 === 0 ? " if false {} " : " _ = 0; "}${source.slice(bIdx + 1)}`;
    }
  } else if (rel.endsWith(".rs")) {
    for (const m of masked.matchAll(/\bfn\s+[A-Za-z_]\w*(?:\s*<[^>]*>)?\s*\(/g)) {
      const pEnd = findBalancedParenEnd(masked, (m.index ?? 0) + m[0].length - 1);
      const bIdx = pEnd >= 0 ? findFnBodyOpenBrace(masked, pEnd + 1, false) : -1;
      if (bIdx >= 0) return `${source.slice(0, bIdx + 1)}${variant % 2 === 0 ? " if false {} " : ` let _${id} = (); `}${source.slice(bIdx + 1)}`;
    }
  } else if (rel.endsWith(".cs")) {
    for (const m of masked.matchAll(/\b(?:public|private|internal|protected)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*[A-Za-z0-9_<>,.\s?]+\s+[A-Za-z_]\w*\s*\(/g)) {
      if (/\b(?:class|record|struct|interface)\b/.test(m[0])) continue;
      const pEnd = findBalancedParenEnd(masked, (m.index ?? 0) + m[0].length - 1);
      const bIdx = pEnd >= 0 ? findFnBodyOpenBrace(masked, pEnd + 1, false) : -1;
      if (bIdx >= 0) return `${source.slice(0, bIdx + 1)}${variant % 2 === 0 ? " if (false) {} " : ` var ${id} = 0; _ = ${id}; `}${source.slice(bIdx + 1)}`;
    }
  }
  return `${source}\n`;
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
    const diff = runGitClean(absRoot, ["diff", "--name-only", ref, "--"]);
    if (diff.status === 0) {
      for (const raw of (diff.stdout ?? "").split(/\r?\n/)) {
        const rel = raw.trim();
        if (rel && /\.(?:[cm]?[jt]sx?|py|rs|go|cs)$/.test(rel)) addSafe(rel);
      }
    }
  }
  return [...targets];
}

function linkSingleNodeModuleEntry(
  entry: fs.Dirent,
  paths: { srcDir: string; dstDir: string; absRoot: string; sandboxDir: string },
  stack: Array<[string, string]>,
): void {
  const sPath = path.join(paths.srcDir, entry.name);
  const dPath = path.join(paths.dstDir, entry.name);
  if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) { stack.push([sPath, dPath]); return; }
  if (entry.isSymbolicLink()) {
    try {
      const target = fs.realpathSync(sPath);
      if (target === paths.absRoot || target.startsWith(`${paths.absRoot}${path.sep}`)) {
        fs.symlinkSync(path.join(paths.sandboxDir, path.relative(paths.absRoot, target)), dPath);
        return;
      }
    } catch { return; }
  }
  try { fs.symlinkSync(sPath, dPath); } catch { return; }
}

function linkNodeModulesIntoSandbox(absRoot: string, sandboxDir: string): void {
  const srcNm = path.join(absRoot, "node_modules");
  const dstNm = path.join(sandboxDir, "node_modules");
  if (!fs.existsSync(srcNm)) return;
  const stack: Array<[string, string]> = [[srcNm, dstNm]];
  while (stack.length > 0) {
    const pair = stack.pop();
    if (!pair) continue;
    const [srcDir, dstDir] = pair;
    fs.mkdirSync(dstDir, { recursive: true });
    for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
      linkSingleNodeModuleEntry(entry, { srcDir, dstDir, absRoot, sandboxDir }, stack);
    }
  }
}

const SANDBOX_SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "obj"]);

function copyRepoForIsolatedCanary(repoRoot: string): string {
  const absRoot = fs.realpathSync(path.resolve(repoRoot));
  const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), "t-"));
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const src = path.join(absRoot, entry.name);
    const dst = path.join(sandboxDir, entry.name);
    if (SANDBOX_SKIP_DIRS.has(entry.name)) {
      if (entry.name === "node_modules") linkNodeModulesIntoSandbox(absRoot, sandboxDir);
      else if (entry.name === ".venv" || entry.name === "venv") { try { fs.symlinkSync(src, dst); } catch { continue; } }
      continue;
    }
    fs.cpSync(src, dst, { recursive: true, dereference: false, filter: (p) => p === src || !SANDBOX_SKIP_DIRS.has(path.basename(p)) });
  }
  return sandboxDir;
}

function safeWriteSandboxText(sandboxDir: string, rel: string, content: string): boolean {
  const realSb = fs.realpathSync(sandboxDir);
  const dest = path.resolve(realSb, rel);
  if (dest !== realSb && !dest.startsWith(`${realSb}${path.sep}`)) return false;
  try { if (fs.lstatSync(dest).isSymbolicLink()) fs.unlinkSync(dest); } catch { void 0; }
  const realParent = fs.realpathSync(path.dirname(dest));
  if (realParent !== realSb && !realParent.startsWith(`${realSb}${path.sep}`)) return false;
  fs.writeFileSync(dest, content, "utf8");
  return true;
}

function withOpaqueTmpEnv<T>(baseEnv: NodeJS.ProcessEnv, sandboxDir: string, fn: (env: NodeJS.ProcessEnv) => T): T {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "t-"));
  const pyPaths = [path.join(sandboxDir, "src"), sandboxDir].filter((p) => fs.existsSync(p));
  if (baseEnv.PYTHONPATH) pyPaths.push(baseEnv.PYTHONPATH);
  const env: NodeJS.ProcessEnv = { ...baseEnv, HOME: tmpDir, XDG_CONFIG_HOME: tmpDir, TMPDIR: tmpDir, TMP: tmpDir, TEMP: tmpDir, PYTHONPATH: pyPaths.join(path.delimiter) };
  try { return fn(env); } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
}

function prepareCanaryPlan(options: CanaryOptions): {
  absRoot: string; minKillRate: number; parsedCmd: ReturnType<typeof parseAndValidateCommandArgv>;
  candidates: MutantCandidate[]; tasks: AsyncCanaryTask[]; failReport: (total: number, invalid: number, diag?: string[]) => PlantedFaultReport;
} {
  const absRoot = path.resolve(options.repoRoot);
  const maxMutants = Math.max(1, options.maxMutants ?? 6);
  const minKillRate = Math.max(0.75, options.minKillRate ?? 0.8);
  const failReport = (total: number, invalid: number, diag?: string[]): PlantedFaultReport => ({
    totalMutants: total, killedMutants: 0, survivedMutants: total, invalidKills: invalid,
    killRate: 0, minKillRate, passed: false, survivors: [], ...(diag && diag.length > 0 ? { invalidDiagnostics: diag } : {}),
  });
  const parsedCmd = parseAndValidateCommandArgv("canary", options.testCmd, absRoot);
  if (parsedCmd.error) return { absRoot, minKillRate, parsedCmd, candidates: [], tasks: [], failReport };
  const targets = resolveTargetFiles(options).sort();
  const seedHasher = crypto.createHash("sha256").update(options.testCmd).update(process.env.GITHUB_RUN_ID ?? process.env.VSTACK_CANARY_NONCE ?? "");
  for (const rel of targets) seedHasher.update(rel).update(fs.readFileSync(path.join(absRoot, rel), "utf8"));
  const runSeed = seedHasher.digest().readUInt32BE(0);
  const diffLines = options.diffRef ? parseDiffChangedLines(absRoot, options.diffRef) : null;
  const filterArid = options.aridFilter ?? Boolean(options.diffRef);
  const perFileBuckets: MutantCandidate[][] = [];
  for (const rel of seededShuffle(targets, runSeed)) {
    const allowedLines = diffLines?.get(rel);
    if (diffLines && (!allowedLines || allowedLines.size === 0)) continue;
    const source = fs.readFileSync(path.join(absRoot, rel), "utf8");
    const srcLines = filterArid ? source.split(/\r?\n/) : [];
    const rawFound = /\.[cm]?[jt]sx?$/.test(rel) ? collectAstMutants(rel, source, maxMutants * 3, runSeed) : collectFallbackMutants(rel, source, maxMutants * 3, runSeed);
    const found = rawFound.filter((c) => (!allowedLines || allowedLines.has(c.line)) && (!filterArid || !isAridMutationLine(srcLines[c.line - 1] ?? ""))).slice(0, maxMutants);
    if (found.length > 0) perFileBuckets.push(found);
  }
  const candidates: MutantCandidate[] = [];
  for (let round = 0; candidates.length < maxMutants; round++) {
    let added = false;
    for (const bucket of perFileBuckets) {
      const c = bucket[round];
      if (c && candidates.length < maxMutants) { candidates.push(c); added = true; }
    }
    if (!added) break;
  }
  const uniqueTargetFiles = [...new Set(candidates.map((c) => c.file))];
  const pickNoOpTarget = (idx: number): string => uniqueTargetFiles[(runSeed + idx) % uniqueTargetFiles.length] ?? uniqueTargetFiles[0] ?? "";
  const rawTasks: AsyncCanaryTask[] = [{ kind: "noop", variant: runSeed % 3, targetRel: pickNoOpTarget(0) }, ...(candidates.length >= 2 ? [{ kind: "noop" as const, variant: (runSeed + 1) % 3, targetRel: pickNoOpTarget(1) }] : []), ...candidates.map((mutant) => ({ kind: "mutant" as const, mutant }))];
  return { absRoot, minKillRate, parsedCmd, candidates, tasks: seededShuffle(rawTasks, runSeed ^ 0x9e3779b9), failReport };
}

export function runPlantedFaultCanary(options: CanaryOptions): PlantedFaultReport {
  const plan = prepareCanaryPlan(options);
  if (plan.parsedCmd.error) return plan.failReport(0, 1, [plan.parsedCmd.error]);
  if (plan.candidates.length === 0) return plan.failReport(0, 0);
  const baseEnv = scrubChildEnv();
  const withFresh = <T>(fn: (sb: string) => T): T => { const sb = copyRepoForIsolatedCanary(plan.absRoot); try { return fn(sb); } finally { fs.rmSync(sb, { recursive: true, force: true }); } };
  const baselineStart = performance.now();
  const baselineRun = withFresh((sb) => withOpaqueTmpEnv(baseEnv, sb, (env) => runArgvChain(plan.parsedCmd.steps, { cwd: sb, env, timeoutMs: 120_000, stepCwds: plan.parsedCmd.stepCwds })));
  const taskTimeoutMs = Math.round(Math.max(25_000, Math.min(120_000, Math.max(500, Math.round(performance.now() - baselineStart)) * 6)));
  const baseCounts = parseRunnerTestCounts(stripAnsi(`${baselineRun.stdout}\n${baselineRun.stderr}`), plan.parsedCmd.steps);
  if (baselineRun.status !== 0 || (baseCounts.hasTestRunner && (!baseCounts.matched || baseCounts.passed <= 0 || baseCounts.failed > 0))) return plan.failReport(plan.candidates.length, plan.candidates.length, ["baseline failed"]);
  let killed = 0; let invalidKills = 0; const survivors: PlantedFaultSurvivor[] = []; const invalidDiagnostics: string[] = [];
  for (const task of plan.tasks) {
    if (task.kind === "noop") {
      const ok = withFresh((sb) => {
        if (!safeWriteSandboxText(sb, task.targetRel, insertSemanticNoOp(task.targetRel, fs.readFileSync(path.join(sb, task.targetRel), "utf8"), task.variant))) return false;
        const res = withOpaqueTmpEnv(baseEnv, sb, (env) => runArgvChain(plan.parsedCmd.steps, { cwd: sb, env, timeoutMs: taskTimeoutMs, stepCwds: plan.parsedCmd.stepCwds }));
        if (res.status !== 0) return false;
        const c = parseRunnerTestCounts(stripAnsi(`${res.stdout}\n${res.stderr}`), plan.parsedCmd.steps);
        return !c.hasTestRunner || (c.matched && c.passed > 0 && c.failed === 0);
      });
      if (!ok) return plan.failReport(plan.candidates.length, plan.candidates.length, [`noop failed on ${task.targetRel}`]);
      continue;
    }
    const m = task.mutant;
    const orig = fs.readFileSync(path.join(plan.absRoot, m.file), "utf8");
    const mut = `${orig.slice(0, m.start)}${m.replacement}${orig.slice(m.end)}`;
    if (/\.[cm]?[jt]sx?$/.test(m.file) && parseSync(m.file, mut).errors.length > 0) { invalidKills += 1; invalidDiagnostics.push(`${m.file}:${m.line} (parse error)`); continue; }
    const execMut = () => withFresh((sb) => {
      if (!safeWriteSandboxText(sb, m.file, mut)) return { outcome: "invalid" as const, diagnostic: "sandbox write failed", retryable: false };
      const t0 = performance.now();
      const res = withOpaqueTmpEnv(baseEnv, sb, (env) => runArgvChain(plan.parsedCmd.steps, { cwd: sb, env, timeoutMs: taskTimeoutMs, stepCwds: plan.parsedCmd.stepCwds }));
      const elapsed = performance.now() - t0;
      const cls = classifyCanaryOutcome(res, elapsed, taskTimeoutMs, plan.parsedCmd.steps);
      const retryable = cls.outcome === "invalid" && (res.signal !== null || res.error !== undefined) && isRetryableCanarySignal(res, elapsed, taskTimeoutMs);
      return { ...cls, retryable };
    });
    let res = execMut();
    if (res.retryable) res = execMut();
    if (res.outcome === "killed") killed += 1;
    else if (res.outcome === "survived") survivors.push({ file: m.file, line: m.line, operator: m.operator, original: m.original, mutated: m.mutated });
    else { invalidKills += 1; invalidDiagnostics.push(`${m.file}:${m.line} (${res.diagnostic !== undefined ? res.diagnostic : "invalid"})`); }
  }
  const killRate = Number((killed / plan.candidates.length).toFixed(4));
  return { totalMutants: plan.candidates.length, killedMutants: killed, survivedMutants: survivors.length, invalidKills, killRate, minKillRate: plan.minKillRate, passed: killed > 0 && invalidKills === 0 && killRate >= plan.minKillRate, survivors, ...(invalidDiagnostics.length > 0 ? { invalidDiagnostics } : {}) };
}

export async function runPlantedFaultCanaryAsync(options: CanaryOptions): Promise<PlantedFaultReport> {
  const plan = prepareCanaryPlan(options);
  if (plan.parsedCmd.error) return plan.failReport(0, 1, [plan.parsedCmd.error]);
  if (plan.candidates.length === 0) return plan.failReport(0, 0);
  return executeCanaryPlanAsync({ absRoot: plan.absRoot, minKillRate: plan.minKillRate, concurrency: options.concurrency, steps: plan.parsedCmd.steps, stepCwds: plan.parsedCmd.stepCwds, candidatesCount: plan.candidates.length, tasks: plan.tasks, baseEnv: scrubChildEnv(), copySandbox: copyRepoForIsolatedCanary, safeWrite: safeWriteSandboxText, insertNoOp: insertSemanticNoOp, failReport: plan.failReport });
}
