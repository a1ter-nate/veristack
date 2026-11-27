export interface ScalingSample {
  n: number;
  timeMs: number;
  memoryBytes?: number;
}

export interface BigOThresholds {
  maxTimeExponent: number;
  maxSpaceExponent?: number;
}

export interface EmpiricalBigOResult {
  sampleCount: number;
  timeExponent: number;
  timeR2: number;
  timeClass: string;
  spaceExponent: number | null;
  spaceR2: number | null;
  spaceClass: string | null;
  passed: boolean;
  reasons: string[];
}

function fitLogLogSlope(xs: readonly number[], ys: readonly number[]): { slope: number; r2: number } {
  const pairs: Array<[number, number]> = [];
  for (let i = 0; i < xs.length; i++) {
    const x = xs[i] ?? 0;
    const y = ys[i] ?? 0;
    if (x > 0 && y > 0) pairs.push([Math.log(x), Math.log(y)]);
  }
  if (pairs.length < 2) return { slope: 0, r2: 0 };

  const meanX = pairs.reduce((acc, [x]) => acc + x, 0) / pairs.length;
  const meanY = pairs.reduce((acc, [, y]) => acc + y, 0) / pairs.length;

  let cov = 0;
  let varX = 0;
  let varY = 0;
  for (const [x, y] of pairs) {
    const dx = x - meanX;
    const dy = y - meanY;
    cov += dx * dy;
    varX += dx * dx;
    varY += dy * dy;
  }

  if (varX === 0) return { slope: 0, r2: 0 };
  const slope = cov / varX;
  const r2 = varY === 0 ? 1 : (cov * cov) / (varX * varY);
  return {
    slope: Number(slope.toFixed(3)),
    r2: Number(Math.max(0, Math.min(1, r2)).toFixed(4)),
  };
}

export function classifyExponent(alpha: number): string {
  if (alpha < 0.2) return "O(1)";
  if (alpha < 0.65) return "O(log n / sqrt n)";
  if (alpha < 1.15) return "O(n)";
  if (alpha < 1.45) return "O(n log n)";
  if (alpha < 2.35) return "O(n^2)";
  return "O(n^3+)";
}

function checkTailAndInterceptScaling(
  ordered: readonly ScalingSample[],
  maxTimeExponent: number,
  reasons: string[],
): void {
  if (ordered.length < 4) return;
  const tail = ordered.slice(Math.min(Math.floor(ordered.length / 2), ordered.length - 3));
  const tailMinN = tail[0]?.n ?? 1;
  const tailMaxN = tail[tail.length - 1]?.n ?? 1;
  if (tail.length >= 3 && tailMaxN / tailMinN >= 2) {
    const tailFit = fitLogLogSlope(tail.map((s) => s.n), tail.map((s) => s.timeMs));
    if (tailFit.r2 >= 0.65 && tailFit.slope > maxTimeExponent + 0.2) {
      reasons.push(`Upper-half tail scaling exponent ${tailFit.slope} (${classifyExponent(tailFit.slope)}) exceeds budget <= ${maxTimeExponent} (padded small-n tail).`);
    }
  }
  const prev = ordered[ordered.length - 2];
  const last = ordered[ordered.length - 1];
  if (prev && last && last.n > prev.n && last.timeMs > prev.timeMs) {
    const finalStepSlope = Math.log(last.timeMs / prev.timeMs) / Math.log(last.n / prev.n);
    if (finalStepSlope > maxTimeExponent + 0.5) {
      reasons.push(`Final scaling step exponent ${finalStepSlope.toFixed(3)} exceeds budget <= ${maxTimeExponent} (sudden super-linear jump at largest n).`);
    }
  }
  const first = ordered[0];
  if (!first || !last || last.timeMs - first.timeMs <= 0.5) return;
  const mids: number[] = [];
  const marginals: number[] = [];
  for (let i = 0; i < ordered.length - 1; i++) {
    const a = ordered[i]; const b = ordered[i + 1];
    if (!a || !b || b.n <= a.n) continue;
    const dt = b.timeMs - a.timeMs;
    if (dt <= 0) { mids.length = 0; break; }
    mids.push((a.n + b.n) / 2);
    marginals.push(dt / (b.n - a.n));
  }
  if (mids.length >= 3) {
    const marginalFit = fitLogLogSlope(mids, marginals);
    const inferredExp = Number((1 + marginalFit.slope).toFixed(3));
    if (marginalFit.r2 >= 0.85 && inferredExp > maxTimeExponent + 0.25) {
      reasons.push(`Intercept-adjusted time scaling exponent ${inferredExp} (${classifyExponent(inferredExp)}) exceeds budget <= ${maxTimeExponent} (constant overhead masking super-linear growth).`);
    }
  }
}

export function fitEmpiricalBigO(
  samples: readonly ScalingSample[],
  thresholds: BigOThresholds = { maxTimeExponent: 1.45 },
): EmpiricalBigOResult {
  const fail = (timeClass: string, reasons: string[]): EmpiricalBigOResult => ({
    sampleCount: samples.length, timeExponent: 0, timeR2: 0, timeClass, spaceExponent: null, spaceR2: null, spaceClass: null, passed: false, reasons,
  });
  if (!Number.isFinite(thresholds.maxTimeExponent) || thresholds.maxTimeExponent <= 0 || thresholds.maxTimeExponent > 2.5) {
    return fail("invalid_threshold", [`Invalid maxTimeExponent (${String(thresholds.maxTimeExponent)}); must be in (0, 2.5].`]);
  }
  if (thresholds.maxSpaceExponent !== undefined && (!Number.isFinite(thresholds.maxSpaceExponent) || thresholds.maxSpaceExponent <= 0 || thresholds.maxSpaceExponent > 2.5)) {
    return fail("invalid_threshold", [`Invalid maxSpaceExponent (${String(thresholds.maxSpaceExponent)}); must be in (0, 2.5].`]);
  }
  if (!Array.isArray(samples) || samples.length < 3) {
    return fail("insufficient_samples", ["At least 3 scaling sizes (e.g., N, 2N, 4N, 8N) are required to fit empirical Big-O."]);
  }
  if (samples.some((s) => !s || typeof s.n !== "number" || typeof s.timeMs !== "number" || !Number.isFinite(s.n) || !Number.isFinite(s.timeMs) || s.n <= 0 || s.timeMs <= 0)) {
    return fail("invalid_samples", ["All scaling samples must have finite positive n and timeMs > 0."]);
  }
  const distinctN = new Set(samples.map((s) => s.n));
  if (distinctN.size < 3) return fail("degenerate_samples", [`At least 3 distinct input sizes n are required (found ${distinctN.size}).`]);

  const ordered = [...samples].sort((a, b) => a.n - b.n);
  const minN = ordered[0]?.n ?? 1; const maxN = ordered[ordered.length - 1]?.n ?? 1;
  if (maxN / minN < 2) return fail("degenerate_samples", [`Input size span max(n)/min(n) = ${(maxN / minN).toFixed(2)} is < 2x (need at least 2x scaling range).`]);

  const times = ordered.map((s) => s.timeMs);
  const timeFit = fitLogLogSlope(ordered.map((s) => s.n), times);
  const timeClass = classifyExponent(timeFit.slope);
  const trulyFlatConstant = Math.max(...times) / Math.max(Math.min(...times), 1e-9) <= 1.25;
  const memPairs = ordered.filter((s) => typeof s.memoryBytes === "number" && Number.isFinite(s.memoryBytes) && s.memoryBytes > 0);
  const spaceFit = memPairs.length >= 3 && new Set(memPairs.map((s) => s.n)).size >= 3 ? fitLogLogSlope(memPairs.map((s) => s.n), memPairs.map((s) => s.memoryBytes ?? 0)) : null;
  const spaceClass = spaceFit ? classifyExponent(spaceFit.slope) : null;

  const reasons: string[] = [];
  if (!trulyFlatConstant && timeFit.r2 < 0.5) reasons.push(`Log-log fit R2=${timeFit.r2} is below 0.5 reliability floor (noisy or non-monotonic timings).`);
  if (timeFit.slope > thresholds.maxTimeExponent) reasons.push(`Time scaling exponent ${timeFit.slope} (${timeClass}) exceeds budget <= ${thresholds.maxTimeExponent}.`);
  checkTailAndInterceptScaling(ordered, thresholds.maxTimeExponent, reasons);
  if (typeof thresholds.maxSpaceExponent === "number" && spaceFit !== null && spaceFit.slope > thresholds.maxSpaceExponent) {
    reasons.push(`Space scaling exponent ${spaceFit.slope} (${spaceClass}) exceeds budget <= ${thresholds.maxSpaceExponent}.`);
  }

  return {
    sampleCount: ordered.length, timeExponent: timeFit.slope, timeR2: timeFit.r2, timeClass,
    spaceExponent: spaceFit ? spaceFit.slope : null, spaceR2: spaceFit ? spaceFit.r2 : null, spaceClass,
    passed: reasons.length === 0, reasons,
  };
}

export function measureEmpiricalBigO<TInput>(
  buildInput: (n: number, trial: number) => TInput,
  run: (input: TInput) => unknown,
  scales: readonly number[],
  options: { repeats?: number; maxTimeExponent?: number } = {},
): { samples: ScalingSample[]; result: EmpiricalBigOResult } {
  if (!Array.isArray(scales)) throw new Error("scales must be an array.");
  const repeats = Math.max(1, options.repeats ?? 3);
  if (repeats < 1) throw new Error("repeats must be positive.");
  if (scales.length > 0) run(buildInput(scales[0] ?? 16, 0));

  const samples: ScalingSample[] = [];
  for (const n of scales) {
    const timings: number[] = [];
    for (let r = 1; r <= repeats; r++) {
      const input = buildInput(n, r);
      const t0 = performance.now();
      const cpu0 = process.cpuUsage();
      run(input);
      const cpu = process.cpuUsage(cpu0);
      const cpuMs = (cpu.user + cpu.system) / 1000;
      const dt = cpuMs > 0 ? cpuMs : performance.now() - t0;
      timings.push(Math.max(dt, 0.001));
    }
    timings.sort((a, b) => a - b);
    const median = timings[Math.floor(timings.length / 2)] ?? 0.001;
    samples.push({ n, timeMs: Number(median.toFixed(4)) });
  }

  const result = fitEmpiricalBigO(samples, { maxTimeExponent: options.maxTimeExponent ?? 1.45 });
  return { samples, result };
}
