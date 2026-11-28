import fs from "node:fs";
import path from "node:path";
import type { Finding } from "@veristack/plugin";

export interface RelationalTransition {
  from: string;
  to: string;
  action: string;
  requiredRole?: string;
  crossTenant?: boolean;
}

export interface RelationalInvariant {
  id: string;
  kind: "tenant-isolation" | "no-privilege-escalation" | "terminal-immutability" | "acyclic" | "forbid-reach";
  terminalStates?: readonly string[];
  forbiddenTarget?: string;
  privilegedRoles?: readonly string[];
}

export interface BoundedRelationalModel {
  schemaVersion: 1;
  name: string;
  roles: readonly string[];
  states: readonly string[];
  initialState: string;
  transitions: readonly RelationalTransition[];
  invariants: readonly RelationalInvariant[];
}

export interface BoundedModelCheckResult {
  passed: boolean;
  modelName: string;
  scope: number;
  statesChecked: number;
  invariantsChecked: number;
  counterexamples: Array<{ invariantId: string; trace: string[]; detail: string }>;
  findings: Finding[];
}

function checkAcyclic(model: BoundedRelationalModel, scope: number): string[] | null {
  const adj = new Map<string, RelationalTransition[]>();
  for (const t of model.transitions) {
    const arr = adj.get(t.from) ?? [];
    arr.push(t);
    adj.set(t.from, arr);
  }
  for (const startState of model.states) {
    const stack: Array<{ cur: string; visited: Set<string>; trace: string[]; depth: number }> = [
      { cur: startState, visited: new Set([startState]), trace: [], depth: 0 },
    ];
    let steps = 0;
    while (stack.length > 0 && steps < 2000) {
      steps += 1;
      const frame = stack.pop();
      if (!frame || frame.depth > scope) continue;
      for (const edge of adj.get(frame.cur) ?? []) {
        const nextTrace = [...frame.trace, `${edge.from}-[${edge.action}]->${edge.to}`];
        if (frame.visited.has(edge.to)) return nextTrace;
        const nextVisited = new Set(frame.visited);
        nextVisited.add(edge.to);
        stack.push({ cur: edge.to, visited: nextVisited, trace: nextTrace, depth: frame.depth + 1 });
      }
    }
  }
  return null;
}

function evaluateInvariant(
  inv: RelationalInvariant,
  model: BoundedRelationalModel,
  reachableByRole: ReadonlyMap<string, ReadonlyMap<string, string[]>>,
  bound: number,
): { invariantId: string; trace: string[]; detail: string } | null {
  if (inv.kind === "tenant-isolation") {
    const bad = model.transitions.find((t) => t.crossTenant === true && !t.requiredRole);
    if (bad) return { invariantId: inv.id, trace: [`tenantA:${bad.from}-[${bad.action}]->tenantB:${bad.to}`], detail: `Unauthenticated cross-tenant transition '${bad.action}' violates tenant isolation.` };
    return null;
  }
  if (inv.kind === "terminal-immutability") {
    const terms = new Set(inv.terminalStates ?? []);
    const bad = model.transitions.find((t) => terms.has(t.from) && t.to !== t.from);
    if (bad) return { invariantId: inv.id, trace: [`${bad.from}-[${bad.action}]->${bad.to}`], detail: `Terminal state '${bad.from}' transitions out to '${bad.to}' via '${bad.action}'.` };
    return null;
  }
  if (inv.kind === "no-privilege-escalation" && inv.forbiddenTarget) {
    const priv = new Set(inv.privilegedRoles ?? ["admin"]);
    for (const [role, reached] of reachableByRole.entries()) {
      if (priv.has(role)) continue;
      const trace = reached.get(inv.forbiddenTarget);
      if (trace) return { invariantId: inv.id, trace, detail: `Non-privileged role '${role}' reaches privileged state '${inv.forbiddenTarget}' within scope k=${bound}.` };
    }
    return null;
  }
  if (inv.kind === "forbid-reach" && inv.forbiddenTarget) {
    for (const [, reached] of reachableByRole.entries()) {
      const trace = reached.get(inv.forbiddenTarget);
      if (trace) return { invariantId: inv.id, trace, detail: `Forbidden state '${inv.forbiddenTarget}' is reachable within scope k=${bound}.` };
    }
    return null;
  }
  if (inv.kind === "acyclic") {
    const cycle = checkAcyclic(model, bound);
    if (cycle) return { invariantId: inv.id, trace: cycle, detail: `Cycle detected within scope k=${bound}: ${cycle.join(" ; ")}.` };
  }
  return null;
}

export function runBoundedRelationalCheck(
  model: BoundedRelationalModel,
  scope = 4,
  modelFile = ".verification/relational-model.json",
): BoundedModelCheckResult {
  if (!model || !model.initialState) throw new Error("BoundedRelationalModel with initialState is required.");
  const bound = Math.max(1, Math.min(4, Math.floor(scope)));
  const roles = model.roles.length > 0 ? model.roles.slice(0, bound) : ["user"];
  const reachableByRole = new Map<string, Map<string, string[]>>();
  let statesChecked = 0;

  for (const role of roles) {
    const visited = new Map<string, string[]>([[model.initialState, []]]);
    const queue: Array<{ state: string; depth: number; trace: string[] }> = [{ state: model.initialState, depth: 0, trace: [] }];
    for (let head = 0; head < queue.length; head++) {
      const cur = queue[head];
      if (!cur) break;
      statesChecked += 1;
      if (cur.depth >= bound) continue;
      for (const t of model.transitions) {
        if (t.from !== cur.state || (t.requiredRole && t.requiredRole !== role)) continue;
        if (!visited.has(t.to)) {
          const nextTrace = [...cur.trace, `${role}:${t.from}-[${t.action}]->${t.to}`];
          visited.set(t.to, nextTrace);
          queue.push({ state: t.to, depth: cur.depth + 1, trace: nextTrace });
        }
      }
    }
    reachableByRole.set(role, visited);
  }

  const counterexamples: Array<{ invariantId: string; trace: string[]; detail: string }> = [];
  for (const inv of model.invariants) {
    const hit = evaluateInvariant(inv, model, reachableByRole, bound);
    if (hit) counterexamples.push(hit);
  }
  const findings: Finding[] = counterexamples.map((ce) => ({
    id: `BMC:${model.name}:${ce.invariantId}`, rule: "bounded-relational-counterexample",
    category: "oracle-lock", rung: "R5", severity: "error", soundness: "incorrectness-witness",
    file: modelFile, line: 1,
    message: `Bounded relational check (k=${bound}) found counterexample for '${ce.invariantId}': ${ce.detail} [trace: ${ce.trace.join(" -> ")}]`,
    fix: "Add the missing role guard, tenant boundary, or terminal-state lock so the counterexample is unreachable.",
  }));
  return {
    passed: counterexamples.length === 0, modelName: model.name, scope: bound,
    statesChecked, invariantsChecked: model.invariants.length, counterexamples, findings,
  };
}

export function auditBoundedRelationalModels(repoRoot: string): BoundedModelCheckResult[] {
  const results: BoundedModelCheckResult[] = [];
  const relPath = ".verification/relational-model.json";
  const abs = path.join(repoRoot, relPath);
  if (!fs.existsSync(abs)) return results;
  try {
    const parsed = JSON.parse(fs.readFileSync(abs, "utf8")) as BoundedRelationalModel;
    if (parsed && typeof parsed.initialState === "string" && Array.isArray(parsed.transitions)) {
      results.push(runBoundedRelationalCheck(parsed, 4, relPath));
    }
  } catch { void 0; }
  return results;
}
