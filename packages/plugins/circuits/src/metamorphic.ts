import fs from "node:fs";
import path from "node:path";

export type MetamorphicRelationKind = "permutation" | "monotonicity" | "idempotence" | "scale-equivalence";

export interface MetamorphicCheckResult {
  passed: boolean;
  relation: MetamorphicRelationKind;
  trials: number;
  failureDetail?: string;
}

export function checkMetamorphicRelation<TInput, TOutput>(opts: {
  relation: MetamorphicRelationKind;
  inputs: readonly TInput[];
  transform: (input: TInput) => TInput;
  evaluate: (input: TInput) => TOutput;
  assertRelation: (baseOut: TOutput, followUpOut: TOutput, baseIn: TInput, followUpIn: TInput) => boolean;
}): MetamorphicCheckResult {
  if (!Array.isArray(opts.inputs) || opts.inputs.length === 0) {
    throw new Error("Metamorphic check requires at least 1 input.");
  }
  for (let i = 0; i < opts.inputs.length; i++) {
    const baseIn = opts.inputs[i] as TInput;
    const followUpIn = opts.transform(baseIn);
    const baseOut = opts.evaluate(baseIn);
    const followUpOut = opts.evaluate(followUpIn);
    if (!opts.assertRelation(baseOut, followUpOut, baseIn, followUpIn)) {
      return {
        passed: false,
        relation: opts.relation,
        trials: i + 1,
        failureDetail: `Metamorphic '${opts.relation}' violated on input #${i + 1}: base=${JSON.stringify(baseOut)} followUp=${JSON.stringify(followUpOut)}`,
      };
    }
  }
  return { passed: true, relation: opts.relation, trials: opts.inputs.length };
}

export interface CrossSurfaceParityResult {
  passed: boolean;
  surfaces: string[];
  mismatches: string[];
}

export function checkCrossSurfaceParity<TInput, TOutput>(
  inputs: readonly TInput[],
  surfaces: Readonly<Record<string, (input: TInput) => TOutput>>,
  normalize: (out: TOutput) => string = (out) => JSON.stringify(out),
): CrossSurfaceParityResult {
  const names = Object.keys(surfaces).sort();
  if (names.length < 2) throw new Error("Cross-surface parity requires at least 2 surfaces (e.g. http, cli, mcp).");
  const mismatches: string[] = [];
  for (let idx = 0; idx < inputs.length; idx++) {
    const inp = inputs[idx] as TInput;
    const refName = names[0] ?? "";
    const refFn = surfaces[refName];
    if (!refFn) continue;
    const refVal = normalize(refFn(inp));
    for (const otherName of names.slice(1)) {
      const otherFn = surfaces[otherName];
      if (!otherFn) continue;
      const otherVal = normalize(otherFn(inp));
      if (otherVal !== refVal) {
        mismatches.push(`input#${idx}: ${refName}=${refVal} !== ${otherName}=${otherVal}`);
      }
    }
  }
  return { passed: mismatches.length === 0, surfaces: names, mismatches };
}

export interface CorpusSeedEntry {
  property: string;
  seed: number;
  minimizedInput: unknown;
  recordedAt: string;
}

export function createCorpusSeedStore(seedFilePath: string): {
  load: () => CorpusSeedEntry[];
  record: (entry: Omit<CorpusSeedEntry, "recordedAt">) => CorpusSeedEntry[];
} {
  const resolved = path.resolve(seedFilePath);
  const load = (): CorpusSeedEntry[] => {
    if (!fs.existsSync(resolved)) return [];
    try {
      const raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as { seeds?: CorpusSeedEntry[] };
      return Array.isArray(raw.seeds) ? raw.seeds : [];
    } catch { return []; }
  };
  const record = (entry: Omit<CorpusSeedEntry, "recordedAt">): CorpusSeedEntry[] => {
    const current = load();
    const exists = current.some((s) => s.property === entry.property && s.seed === entry.seed);
    if (!exists) current.push({ ...entry, recordedAt: new Date().toISOString() });
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, `${JSON.stringify({ schemaVersion: 1, seeds: current }, null, 2)}\n`, "utf8");
    return current;
  };
  return { load, record };
}
