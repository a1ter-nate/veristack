import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseSync } from "oxc-parser";
import type { PlantedFaultReport, PlantedFaultSurvivor } from "@veristack/plugin";
import { parseRunnerTestCounts, stripAnsi } from "./runner-metrics.ts";

export interface CanaryRunResult {
  status: number;
  stdout: string;
  stderr: string;
  signal: NodeJS.Signals | null;
  error?: Error;
}

export interface AsyncCanaryTaskMutant {
  file: string;
  line: number;
  start: number;
  end: number;
  replacement: string;
  operator: string;
  original: string;
  mutated: string;
}

export type AsyncCanaryTask =
  | { kind: "noop"; variant: number; targetRel: string }
  | { kind: "mutant"; mutant: AsyncCanaryTaskMutant };

const MAX_BUFFER_BYTES = 16 * 1024 * 1024;
const nativeSetTimeout = globalThis.setTimeout.bind(globalThis);
const nativeClearTimeout = globalThis.clearTimeout.bind(globalThis);

const COMPILE_OR_RUNTIME_CRASH =
  /(?:SyntaxError:\s*(?:Unexpected|invalid\s+syntax|Parse\s+error)|IndentationError:|NameError:|ImportError:|Cannot\s+find\s+module|\bTS\d{4}:|\bCS\d{4}:|error\[E\d{4}\]|cannot\s+find\s+package|syntax\s+error:|undefined:\s+\w+|compilation\s+failed|build\s+failed)/i;

const STRICT_TEST_FAILURE =
  /(?:\b[1-9]\d*\s+fail(?:ed|ure|ures)?\b|AssertionError|AssertionFailed|Expected\s+values|assertion\s+`?left|test\s+result:\s*FAILED|---\s+FAIL:|^FAIL\s+\S|Failed!\s+-|Failed:\s*[1-9]\d*|not\s+ok\s+\d+|✗|×)/m;

interface SpawnStepSpec {
  bin: string;
  args: readonly string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
}

function spawnStepAsync(spec: SpawnStepSpec): Promise<CanaryRunResult> {
  const { bin, args, cwd, env, timeoutMs } = spec;
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let overflowed = false;
    const child = spawn(bin, [...args], { cwd, shell: false, env, stdio: ["ignore", "pipe", "pipe"] });
    const finish = (res: CanaryRunResult): void => {
      if (settled) return;
      settled = true;
      nativeClearTimeout(timer);
      resolve(res);
    };
    child.on("error", (err) => finish({ status: 1, stdout, stderr, signal: null, error: err }));
    const timer = nativeSetTimeout(() => {
      timedOut = true;
      try { child.kill("SIGTERM"); } catch { void 0; }
    }, timeoutMs);
    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdout.length + chunk.length > MAX_BUFFER_BYTES) {
        overflowed = true;
        try { child.kill("SIGTERM"); } catch { void 0; }
        return;
      }
      stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length + chunk.length > MAX_BUFFER_BYTES) {
        overflowed = true;
        try { child.kill("SIGTERM"); } catch { void 0; }
        return;
      }
      stderr += chunk.toString("utf8");
    });
    child.on("close", (code, sig) => {
      if (timedOut) {
        finish({ status: code ?? 1, stdout, stderr, signal: sig ?? "SIGTERM", error: Object.assign(new Error("ETIMEDOUT"), { code: "ETIMEDOUT" }) });
        return;
      }
      if (overflowed) {
        finish({ status: code ?? 1, stdout, stderr, signal: sig, error: Object.assign(new Error("ENOBUFS"), { code: "ENOBUFS" }) });
        return;
      }
      finish({ status: code ?? 1, stdout, stderr, signal: sig ?? null });
    });
  });
}

interface ArgvChainSpec {
  steps: readonly string[][];
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  stepCwds?: readonly string[];
}

async function runArgvChainAsync(spec: ArgvChainSpec): Promise<CanaryRunResult> {
  const { steps, cwd, env, timeoutMs, stepCwds } = spec;
  if (steps.length === 0) return { status: 1, stdout: "", stderr: "empty argv chain", signal: null };
  let stdout = "";
  let stderr = "";
  for (let idx = 0; idx < steps.length; idx++) {
    const argv = steps[idx] ?? [];
    const bin = argv[0] ?? "";
    if (!bin) return { status: 1, stdout, stderr: `${stderr}\nempty argv`, signal: null };
    const relSub = stepCwds?.[idx];
    const resolvedSub = relSub ? path.resolve(cwd, relSub) : cwd;
    const stepCwd = relSub && fs.existsSync(resolvedSub) ? resolvedSub : cwd;
    const res = await spawnStepAsync({ bin, args: argv.slice(1), cwd: stepCwd, env, timeoutMs });
    stdout += res.stdout;
    stderr += res.stderr;
    if (res.error || res.signal || res.status !== 0) {
      return { status: res.status, stdout, stderr, signal: res.signal, error: res.error };
    }
  }
  return { status: 0, stdout, stderr, signal: null };
}

export function isRetryableCanarySignal(res: CanaryRunResult, elapsedMs: number, taskTimeoutMs: number): boolean {
  const errCode = (res.error as NodeJS.ErrnoException | undefined)?.code;
  const timedOut = (res.signal === "SIGTERM" || errCode === "ETIMEDOUT") && elapsedMs >= taskTimeoutMs * 0.8;
  if (timedOut) return false;
  return Boolean(res.signal || (res.error && errCode !== "ENOENT"));
}

export function classifyCanaryOutcome(
  res: CanaryRunResult,
  elapsedMs: number,
  taskTimeoutMs: number,
  steps: readonly string[][],
): { outcome: "killed" | "survived" | "invalid"; diagnostic?: string } {
  const cleanCombined = stripAnsi(`${res.stdout}\n${res.stderr}`);
  const errCode = (res.error as NodeJS.ErrnoException | undefined)?.code;
  const timedOut = (res.signal === "SIGTERM" || errCode === "ETIMEDOUT") && elapsedMs >= taskTimeoutMs * 0.8;
  if (timedOut) return { outcome: "killed" };
  if (res.signal || res.error) {
    return { outcome: "invalid", diagnostic: `signal=${res.signal ?? "none"} err=${errCode ?? res.error?.message ?? "unknown"}` };
  }
  if (res.status === 0) return { outcome: "survived" };
  const parsedCounts = parseRunnerTestCounts(cleanCombined, steps);
  const runnerReportedFail = parsedCounts.matched && parsedCounts.failed > 0;
  const crashLines = cleanCombined
    .split(/\r?\n/)
    .filter((l) => !/^\s*(?:Expected|Received|Actual|[-+]\s|AssertionError|expect\(|assert\.)/.test(l))
    .join("\n");
  const crashMatch = COMPILE_OR_RUNTIME_CRASH.exec(crashLines);
  const hasCrash =
    Boolean(crashMatch) &&
    !(runnerReportedFail && /\b(?:AssertionError|AssertionFailed|Expected\s+values|assertion\s+`?left)\b/.test(cleanCombined));
  if (hasCrash) return { outcome: "invalid", diagnostic: `crash=${crashMatch?.[0] ?? "compile/runtime"}` };
  if (!runnerReportedFail && !STRICT_TEST_FAILURE.test(cleanCombined)) {
    return { outcome: "invalid", diagnostic: `exit=${res.status} without test failure marker` };
  }
  return { outcome: "killed" };
}

async function runWithBoundedConcurrency<T>(
  items: readonly T[],
  limit: number | undefined,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  const cpuCount = typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  const workers = Math.max(1, Math.min(items.length || 1, limit ?? Math.min(2, Math.max(1, cpuCount - 1))));
  let cursor = 0;
  const next = async (): Promise<void> => {
    while (cursor < items.length) {
      const idx = cursor;
      cursor += 1;
      const item = items[idx];
      if (item !== undefined) await worker(item);
    }
  };
  await Promise.all(Array.from({ length: workers }, () => next()));
}

async function withOpaqueTmpEnvAsync<T>(
  baseEnv: NodeJS.ProcessEnv,
  sandboxDir: string,
  fn: (env: NodeJS.ProcessEnv) => Promise<T>,
): Promise<T> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "t-"));
  const pyPaths = [path.join(sandboxDir, "src"), sandboxDir].filter((p) => fs.existsSync(p));
  if (baseEnv.PYTHONPATH) pyPaths.push(baseEnv.PYTHONPATH);
  const env: NodeJS.ProcessEnv = { ...baseEnv, HOME: tmpDir, XDG_CONFIG_HOME: tmpDir, TMPDIR: tmpDir, TMP: tmpDir, TEMP: tmpDir, PYTHONPATH: pyPaths.join(path.delimiter) };
  try { return await fn(env); } finally { fs.rmSync(tmpDir, { recursive: true, force: true }); }
}

interface CanaryPlanParams {
  absRoot: string;
  minKillRate: number;
  concurrency?: number;
  steps: readonly string[][];
  stepCwds?: readonly string[];
  candidatesCount: number;
  tasks: readonly AsyncCanaryTask[];
  baseEnv: NodeJS.ProcessEnv;
  copySandbox: (root: string) => string;
  safeWrite: (sb: string, rel: string, content: string) => boolean;
  insertNoOp: (rel: string, src: string, variant: number) => string;
  failReport: (total: number, invalid: number, diag?: string[]) => PlantedFaultReport;
}

async function runFreshSandboxAsync<T>(params: CanaryPlanParams, fn: (sb: string) => Promise<T>): Promise<T> {
  const sb = params.copySandbox(params.absRoot);
  try { return await fn(sb); } finally { fs.rmSync(sb, { recursive: true, force: true }); }
}

async function runNoOpCanaryTaskAsync(
  params: CanaryPlanParams,
  task: Extract<AsyncCanaryTask, { kind: "noop" }>,
  taskTimeoutMs: number,
): Promise<string | null> {
  const attempt = async (): Promise<{ ok: boolean; retryable: boolean; detail: string }> =>
    runFreshSandboxAsync(params, async (sb) => {
      if (!params.safeWrite(sb, task.targetRel, params.insertNoOp(task.targetRel, fs.readFileSync(path.join(sb, task.targetRel), "utf8"), task.variant))) {
        return { ok: false, retryable: false, detail: "write failed" };
      }
      const t0 = performance.now();
      const res = await withOpaqueTmpEnvAsync(params.baseEnv, sb, (env) => runArgvChainAsync({ steps: params.steps, cwd: sb, env, timeoutMs: taskTimeoutMs, stepCwds: params.stepCwds }));
      const elapsed = performance.now() - t0;
      if (res.status !== 0) return { ok: false, retryable: isRetryableCanarySignal(res, elapsed, taskTimeoutMs), detail: `status=${res.status} sig=${res.signal ?? "none"}` };
      const c = parseRunnerTestCounts(stripAnsi(`${res.stdout}\n${res.stderr}`), params.steps);
      const ok = !c.hasTestRunner || (c.matched && c.passed > 0 && c.failed === 0);
      return { ok, retryable: false, detail: ok ? "" : `counts matched=${c.matched} passed=${c.passed} failed=${c.failed}` };
    });
  let noopRes = await attempt();
  if (!noopRes.ok && noopRes.retryable) noopRes = await attempt();
  return noopRes.ok ? null : `noop failed on ${task.targetRel} (${noopRes.detail})`;
}

async function runMutantCanaryTaskAsync(
  params: CanaryPlanParams,
  m: AsyncCanaryTaskMutant,
  taskTimeoutMs: number,
): Promise<{ outcome: "killed" | "survived" | "invalid"; diagnostic?: string }> {
  const orig = fs.readFileSync(path.join(params.absRoot, m.file), "utf8");
  const mut = `${orig.slice(0, m.start)}${m.replacement}${orig.slice(m.end)}`;
  if (/\.[cm]?[jt]sx?$/.test(m.file) && parseSync(m.file, mut).errors.length > 0) {
    return { outcome: "invalid", diagnostic: "parse error" };
  }
  const execMut = async () => runFreshSandboxAsync(params, async (sb) => {
    if (!params.safeWrite(sb, m.file, mut)) return { outcome: "invalid" as const, diagnostic: "sandbox write failed", retryable: false };
    const t0 = performance.now();
    const res = await withOpaqueTmpEnvAsync(params.baseEnv, sb, (env) => runArgvChainAsync({ steps: params.steps, cwd: sb, env, timeoutMs: taskTimeoutMs, stepCwds: params.stepCwds }));
    const elapsed = performance.now() - t0;
    const cls = classifyCanaryOutcome(res, elapsed, taskTimeoutMs, params.steps);
    return { ...cls, retryable: cls.outcome === "invalid" && isRetryableCanarySignal(res, elapsed, taskTimeoutMs) };
  });
  let res = await execMut();
  if (res.retryable) res = await execMut();
  return res;
}

export async function executeCanaryPlanAsync(params: CanaryPlanParams): Promise<PlantedFaultReport> {
  const baselineStart = performance.now();
  const baselineRun = await runFreshSandboxAsync(params, (sb) =>
    withOpaqueTmpEnvAsync(params.baseEnv, sb, (env) => runArgvChainAsync({ steps: params.steps, cwd: sb, env, timeoutMs: 120_000, stepCwds: params.stepCwds })),
  );
  const taskTimeoutMs = Math.round(Math.max(25_000, Math.min(120_000, Math.max(500, Math.round(performance.now() - baselineStart)) * 6)));
  const baseCounts = parseRunnerTestCounts(stripAnsi(`${baselineRun.stdout}\n${baselineRun.stderr}`), params.steps);
  if (baselineRun.status !== 0 || (baseCounts.hasTestRunner && (!baseCounts.matched || baseCounts.passed <= 0 || baseCounts.failed > 0))) {
    return params.failReport(params.candidatesCount, params.candidatesCount, ["baseline failed"]);
  }
  let killed = 0;
  let invalidKills = 0;
  let noopFailed: string | null = null;
  const survivors: PlantedFaultSurvivor[] = [];
  const invalidDiagnostics: string[] = [];
  await runWithBoundedConcurrency(params.tasks, params.concurrency, async (task) => {
    if (noopFailed) return;
    if (task.kind === "noop") {
      const err = await runNoOpCanaryTaskAsync(params, task, taskTimeoutMs);
      if (err) noopFailed = err;
      return;
    }
    const m = task.mutant;
    const res = await runMutantCanaryTaskAsync(params, m, taskTimeoutMs);
    if (res.outcome === "killed") killed += 1;
    else if (res.outcome === "survived") survivors.push({ file: m.file, line: m.line, operator: m.operator, original: m.original, mutated: m.mutated });
    else { invalidKills += 1; invalidDiagnostics.push(`${m.file}:${m.line} (${res.diagnostic ?? "invalid"})`); }
  });
  if (noopFailed) return params.failReport(params.candidatesCount, params.candidatesCount, [noopFailed]);
  const killRate = Number((killed / params.candidatesCount).toFixed(4));
  return {
    totalMutants: params.candidatesCount, killedMutants: killed, survivedMutants: survivors.length, invalidKills,
    killRate, minKillRate: params.minKillRate, passed: killed > 0 && invalidKills === 0 && killRate >= params.minKillRate,
    survivors, ...(invalidDiagnostics.length > 0 ? { invalidDiagnostics } : {}),
  };
}
