import fs from "node:fs";
import path from "node:path";
import { isTestFilePath, runGitClean } from "@veristack/plugin";
import { parseAndValidateCommandArgv, runArgvChain, scrubChildEnv } from "@veristack/plugin-control-plane";

export interface LawTargetedMutant {
  lawId: string;
  file: string;
  line: number;
  original: string;
  mutated: string;
}

export interface OrderDependenceResult {
  passed: boolean;
  ordersTested: number;
  testFiles: string[];
  failingOrder?: string;
  detail: string;
}

const ARID_LINE_RE =
  /^\s*(?:console|logger|log)\s*\.\s*(?:log|warn|error|info|debug|trace)\s*\(|\b(?:toString|format[A-Z]\w*)\s*\(|\bthrow\s+new\s+Error\s*\(\s*[`"']|\bassert\.(?:ok|equal|deepEqual)\s*\([^,]+,\s*[`"']/;

export function isAridMutationLine(sourceLine: string): boolean {
  return ARID_LINE_RE.test(sourceLine);
}

export function parseDiffChangedLines(repoRoot: string, diffRef: string): Map<string, Set<number>> {
  const changed = new Map<string, Set<number>>();
  if (!diffRef || diffRef.startsWith("-")) return changed;
  const diff = runGitClean(repoRoot, ["diff", diffRef, "--unified=0", "--no-color"]);
  if (diff.status !== 0) return changed;
  let curFile = "";
  let curLine = 0;
  for (const raw of diff.stdout.split(/\r?\n/)) {
    if (raw.startsWith("+++ b/")) { curFile = raw.slice(6).trim(); continue; }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(raw);
    if (hunk) { curLine = Number(hunk[1]); continue; }
    if (!raw.startsWith("+") || raw.startsWith("+++")) continue;
    if (curFile && curLine > 0) {
      const set = changed.get(curFile) ?? new Set<number>();
      set.add(curLine);
      changed.set(curFile, set);
    }
    curLine += 1;
  }
  return changed;
}

function findFirstLawMutantInFile(repoRoot: string, lawId: string, rel: string): LawTargetedMutant | null {
  const abs = path.join(repoRoot, rel);
  if (!fs.existsSync(abs)) return null;
  const flip: Record<string, string> = { ">=": "<", "<=": ">", "===": "!==", "!==": "===" };
  const lines = fs.readFileSync(abs, "utf8").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (isAridMutationLine(line)) continue;
    const op = /(>=|<=|===|!==)/.exec(line);
    const rep = op?.[1] ? flip[op[1]] : undefined;
    if (op?.[1] && rep) return { lawId, file: rel, line: i + 1, original: line.trim(), mutated: line.replace(op[1], rep).trim() };
  }
  return null;
}

export function synthesizeLawMutants(repoRoot: string): LawTargetedMutant[] {
  if (!repoRoot) throw new Error("repoRoot is required.");
  const lawsDir = path.join(repoRoot, ".verification", "laws");
  if (!fs.existsSync(lawsDir)) return [];
  const mutants: LawTargetedMutant[] = [];
  for (const entry of fs.readdirSync(lawsDir).filter((n) => n.endsWith(".laws.json")).sort()) {
    let doc: Record<string, unknown>;
    try { doc = JSON.parse(fs.readFileSync(path.join(lawsDir, entry), "utf8")) as Record<string, unknown>; } catch { continue; }
    const laws = Array.isArray(doc.laws) ? doc.laws : [];
    for (const rawLaw of laws) {
      if (!rawLaw || typeof rawLaw !== "object") continue;
      const rec = rawLaw as Record<string, unknown>;
      const lawId = typeof rec.id === "string" ? rec.id : entry;
      const targets = Array.isArray(rec.coveredFiles) ? rec.coveredFiles.filter((f): f is string => typeof f === "string") : [];
      for (const rel of targets) {
        const hit = findFirstLawMutantInFile(repoRoot, lawId, rel);
        if (hit) mutants.push(hit);
      }
    }
  }
  return mutants;
}

function deterministicShuffle(items: readonly string[], seed: number): string[] {
  const copy = [...items];
  let state = seed >>> 0;
  for (let i = copy.length - 1; i > 0; i--) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const j = state % (i + 1);
    const a = copy[i]; const b = copy[j];
    if (a !== undefined && b !== undefined) { copy[i] = b; copy[j] = a; }
  }
  return copy;
}

function discoverExplicitTestFiles(repoRoot: string, stepArgv: readonly string[]): string[] {
  const files: string[] = [];
  for (const tok of stepArgv.slice(2)) {
    if (tok.startsWith("-")) continue;
    const abs = path.resolve(repoRoot, tok);
    if (!fs.existsSync(abs)) continue;
    const st = fs.statSync(abs);
    if (st.isFile() && isTestFilePath(tok)) files.push(tok);
    else if (st.isDirectory()) {
      for (const name of fs.readdirSync(abs).sort()) {
        const rel = path.posix.join(tok.replace(/\\/g, "/"), name);
        if (fs.statSync(path.join(abs, name)).isFile() && isTestFilePath(rel)) files.push(rel);
      }
    }
  }
  return [...new Set(files)].sort();
}

export function runOrderDependenceGate(opts: { repoRoot: string; testCmd: string; orders?: number }): OrderDependenceResult {
  const absRoot = path.resolve(opts.repoRoot);
  const ordersCount = Math.max(2, Math.min(5, Math.floor(opts.orders ?? 3)));
  const parsed = parseAndValidateCommandArgv("canary", opts.testCmd, absRoot);
  if (parsed.error || parsed.steps.length === 0) {
    return { passed: false, ordersTested: 0, testFiles: [], detail: parsed.error ?? "invalid test command" };
  }
  const firstStep = parsed.steps[0] ?? [];
  const testFiles = discoverExplicitTestFiles(absRoot, firstStep);
  if (testFiles.length < 2) {
    return { passed: true, ordersTested: 1, testFiles, detail: `Only ${testFiles.length} test file(s) discovered; no cross-file order permutation applicable.` };
  }
  const runnerPrefix = firstStep.slice(0, 2);
  const flags = firstStep.slice(2).filter((a) => a.startsWith("-"));
  const env = scrubChildEnv();
  const plans: Array<{ name: string; files: string[] }> = [
    { name: "forward", files: [...testFiles] },
    { name: "reversed", files: [...testFiles].reverse() },
  ];
  for (let i = 2; i < ordersCount; i++) {
    plans.push({ name: `shuffled-${i}`, files: deterministicShuffle(testFiles, 0x517cc1b7 ^ (i * 2654435761)) });
  }
  let tested = 0;
  for (const plan of plans) {
    tested += 1;
    const res = runArgvChain([[...runnerPrefix, ...flags, ...plan.files]], { cwd: absRoot, env, timeoutMs: 60_000 });
    if (res.status !== 0) {
      return {
        passed: false, ordersTested: tested, testFiles, failingOrder: plan.name,
        detail: `Order-dependence failure in '${plan.name}' order (${plan.files.slice(0, 5).join(", ")}) — tests leak shared state.`,
      };
    }
  }
  return { passed: true, ordersTested: tested, testFiles, detail: `All ${tested} execution orders (forward, reversed, shuffled) passed across ${testFiles.length} test file(s).` };
}
