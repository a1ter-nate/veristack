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
  | { kind: "lit"; value: boolean }
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
      else if (lower === "true") tokens.push({ kind: "lit", value: true });
      else if (lower === "false") tokens.push({ kind: "lit", value: false });
      else tokens.push({ kind: "id", value: word });
      i += word.length;
      continue;
    }
    throw new Error(`Unexpected token near "${expr.slice(i, i + 12)}" in boolean expression.`);
  }
  return tokens;
}

const BOOL_PRECEDENCE: Record<"OR" | "AND" | "NOT", number> = { OR: 1, AND: 2, NOT: 3 };

function applyBoolOp(op: "OR" | "AND" | "NOT", values: boolean[]): void {
  if (op === "NOT") {
    const operand = values.pop();
    if (operand === undefined) throw new Error("Invalid boolean expression syntax.");
    values.push(!operand);
    return;
  }
  const right = values.pop();
  const left = values.pop();
  if (left === undefined || right === undefined) throw new Error("Invalid boolean expression syntax.");
  values.push(op === "AND" ? left && right : left || right);
}

function evalBoolTokens(tokens: readonly BoolToken[], env: Readonly<Record<string, boolean>>): boolean {
  if (tokens.length === 0) throw new Error("Unexpected end of boolean expression.");
  const values: boolean[] = [];
  const ops: Array<"OR" | "AND" | "NOT" | "("> = [];
  let expectOperand = true;
  for (const tok of tokens) {
    if (tok.kind === "lit" || tok.kind === "id") {
      if (!expectOperand) throw new Error("Trailing tokens in boolean expression.");
      values.push(tok.kind === "lit" ? tok.value : env[tok.value] === true);
      expectOperand = false;
      continue;
    }
    if (tok.kind === "lparen") {
      if (!expectOperand) throw new Error("Trailing tokens in boolean expression.");
      ops.push("(");
      continue;
    }
    if (tok.kind === "rparen") {
      if (expectOperand) throw new Error("Invalid boolean expression syntax.");
      while (ops.length > 0 && ops[ops.length - 1] !== "(") {
        const top = ops.pop();
        if (top && top !== "(") applyBoolOp(top, values);
      }
      if (ops.pop() !== "(") throw new Error("Unmatched ')' in boolean expression.");
      expectOperand = false;
      continue;
    }
    if (tok.value === "NOT") {
      if (!expectOperand) throw new Error("Trailing tokens in boolean expression.");
      ops.push("NOT");
      continue;
    }
    if (expectOperand) throw new Error("Invalid boolean expression syntax.");
    const prec = BOOL_PRECEDENCE[tok.value];
    while (ops.length > 0) {
      const top = ops[ops.length - 1];
      if (!top || top === "(" || BOOL_PRECEDENCE[top] < prec) break;
      ops.pop();
      applyBoolOp(top, values);
    }
    ops.push(tok.value);
    expectOperand = true;
  }
  if (expectOperand) throw new Error("Unexpected end of boolean expression.");
  while (ops.length > 0) {
    const top = ops.pop();
    if (!top || top === "(") throw new Error("Unclosed '(' in boolean expression.");
    applyBoolOp(top, values);
  }
  if (values.length !== 1) throw new Error("Trailing tokens in boolean expression.");
  return values[0] === true;
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
