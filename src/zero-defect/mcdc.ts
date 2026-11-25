export interface McdcVector {
  index: number;
  inputs: Record<string, boolean>;
  output: boolean;
  provesIndependent: string[];
}

export interface McdcResult {
  expression: string;
  variables: string[];
  vectors: McdcVector[];
  uncoveredVariables: string[];
}

type BoolToken =
  | { kind: "id"; value: string }
  | { kind: "op"; value: "AND" | "OR" | "NOT" }
  | { kind: "lparen" }
  | { kind: "rparen" };

function tokenizeBoolExpr(expr: string): BoolToken[] {
  const tokens: BoolToken[] = [];
  let i = 0;
  while (i < expr.length) {
    const ch = expr[i] ?? "";
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    if (ch === "(") {
      tokens.push({ kind: "lparen" });
      i += 1;
      continue;
    }
    if (ch === ")") {
      tokens.push({ kind: "rparen" });
      i += 1;
      continue;
    }
    if (ch === "!") {
      tokens.push({ kind: "op", value: "NOT" });
      i += 1;
      continue;
    }
    if (expr.slice(i, i + 2) === "&&") {
      tokens.push({ kind: "op", value: "AND" });
      i += 2;
      continue;
    }
    if (expr.slice(i, i + 2) === "||") {
      tokens.push({ kind: "op", value: "OR" });
      i += 2;
      continue;
    }
    const idMatch = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(expr.slice(i));
    if (idMatch) {
      const word = idMatch[0];
      const lower = word.toLowerCase();
      if (lower === "and") tokens.push({ kind: "op", value: "AND" });
      else if (lower === "or") tokens.push({ kind: "op", value: "OR" });
      else if (lower === "not") tokens.push({ kind: "op", value: "NOT" });
      else tokens.push({ kind: "id", value: word });
      i += word.length;
      continue;
    }
    throw new Error(`Unexpected token near "${expr.slice(i, i + 12)}" in boolean expression.`);
  }
  return tokens;
}

function evalBoolTokens(tokens: readonly BoolToken[], env: Readonly<Record<string, boolean>>): boolean {
  let pos = 0;
  const parseOr = (): boolean => {
    let left = parseAnd();
    while (tokens[pos]?.kind === "op" && tokens[pos]?.value === "OR") {
      pos += 1;
      const right = parseAnd();
      left = left || right;
    }
    return left;
  };
  const parseAnd = (): boolean => {
    let left = parseNot();
    while (tokens[pos]?.kind === "op" && tokens[pos]?.value === "AND") {
      pos += 1;
      const right = parseNot();
      left = left && right;
    }
    return left;
  };
  const parseNot = (): boolean => {
    if (tokens[pos]?.kind === "op" && tokens[pos]?.value === "NOT") {
      pos += 1;
      return !parseNot();
    }
    const tok = tokens[pos];
    if (!tok) throw new Error("Unexpected end of boolean expression.");
    if (tok.kind === "lparen") {
      pos += 1;
      const val = parseOr();
      if (tokens[pos]?.kind !== "rparen") throw new Error("Unclosed '(' in boolean expression.");
      pos += 1;
      return val;
    }
    if (tok.kind === "id") {
      pos += 1;
      return env[tok.value] === true;
    }
    throw new Error("Invalid boolean expression syntax.");
  };
  const value = parseOr();
  if (pos !== tokens.length) throw new Error("Trailing tokens in boolean expression.");
  return value;
}

export function generateMcdcVectors(expression: string): McdcResult {
  const tokens = tokenizeBoolExpr(expression);
  const variables: string[] = [];
  for (const tok of tokens) {
    if (tok.kind === "id" && !variables.includes(tok.value)) variables.push(tok.value);
  }
  if (variables.length === 0 || variables.length > 10) {
    throw new Error(`MC/DC generator supports 1..10 boolean conditions (found ${variables.length}).`);
  }

  const total = 1 << variables.length;
  const outputs: boolean[] = [];
  const rows: Array<Record<string, boolean>> = [];

  for (let mask = 0; mask < total; mask++) {
    const env: Record<string, boolean> = {};
    for (let bit = 0; bit < variables.length; bit++) {
      const name = variables[bit] ?? "";
      env[name] = Boolean((mask >> (variables.length - 1 - bit)) & 1);
    }
    rows.push(env);
    outputs.push(evalBoolTokens(tokens, env));
  }

  const chosen = new Map<number, Set<string>>();
  const uncoveredVariables: string[] = [];

  for (let bit = 0; bit < variables.length; bit++) {
    const name = variables[bit] ?? "";
    const flipMask = 1 << (variables.length - 1 - bit);
    let bestPair: [number, number] | undefined;
    let bestOverlap = -1;

    for (let mask = 0; mask < total; mask++) {
      const partner = mask ^ flipMask;
      if (partner < mask) continue;
      if (outputs[mask] === outputs[partner]) continue;
      const overlap = (chosen.has(mask) ? 1 : 0) + (chosen.has(partner) ? 1 : 0);
      if (overlap > bestOverlap) {
        bestOverlap = overlap;
        bestPair = [mask, partner];
        if (overlap === 2) break;
      }
    }

    if (!bestPair) {
      uncoveredVariables.push(name);
      continue;
    }
    for (const idx of bestPair) {
      const set = chosen.get(idx) ?? new Set<string>();
      set.add(name);
      chosen.set(idx, set);
    }
  }

  const vectors: McdcVector[] = [...chosen.entries()]
    .sort(([a], [b]) => a - b)
    .map(([mask, vars], idx) => ({
      index: idx + 1,
      inputs: rows[mask] ?? {},
      output: outputs[mask] === true,
      provesIndependent: [...vars],
    }));

  return { expression, variables, vectors, uncoveredVariables };
}
