import { parseSync } from "oxc-parser";
import { lineOf, maskCode, type Finding, type ScannedFile } from "@veristack/plugin";

const TERMINAL_OUTCOME_NAMES = new Set([
  "settled", "refused", "done", "closed", "completed", "cancelled", "canceled", "rejected", "paid", "approved",
]);
const RESOURCE_ENTRY_HINT = /(?:timer|interval|setInterval|setTimeout|subscribe|connect|acquire|lock|open|spawn|listener|socket|stream)/i;

type AstRec = Record<string, unknown>;

function isObj(v: unknown): v is AstRec {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function propKeyName(prop: AstRec): string {
  const key = prop.key;
  if (!isObj(key)) return "";
  if (key.type === "Identifier" && typeof key.name === "string") return key.name;
  if (key.type === "Literal" && typeof key.value === "string") return key.value;
  return "";
}

function getObjProp(obj: AstRec, name: string): AstRec | null {
  if (!Array.isArray(obj.properties)) return null;
  for (const p of obj.properties) {
    if (isObj(p) && p.type === "Property" && propKeyName(p) === name) return p;
  }
  return null;
}

function stringVal(node: unknown): string | null {
  return isObj(node) && node.type === "Literal" && typeof node.value === "string" ? node.value : null;
}

function extractTargetsFromTransition(rootVal: unknown, out: Set<string>): void {
  const stack: unknown[] = [rootVal];
  let steps = 0;
  while (stack.length > 0 && steps < 200) {
    steps += 1;
    const val = stack.pop();
    const s = stringVal(val);
    if (s) { out.add(s.replace(/^[#.]+/, "").split(".")[0] ?? s); continue; }
    if (isObj(val) && val.type === "ArrayExpression" && Array.isArray(val.elements)) { for (const item of val.elements) stack.push(item); continue; }
    if (Array.isArray(val)) { for (const item of val) stack.push(item); continue; }
    if (isObj(val) && val.type === "ObjectExpression") {
      const tgtProp = getObjProp(val, "target");
      if (tgtProp) stack.push(tgtProp.value);
    }
  }
}

function checkOverlappingTransitionGuards(
  ctx: { file: ScannedFile; stateName: string; eventName: string; findings: Finding[] },
  arr: unknown[],
): void {
  if (!ctx.file) throw new Error("ScannedFile is required.");
  if (!Array.isArray(arr) || arr.length < 2) return;
  const seenGuards = new Set<string>();
  let unguarded = 0;
  for (const item of arr) {
    if (!isObj(item) || item.type !== "ObjectExpression") continue;
    const gProp = getObjProp(item, "guard") ?? getObjProp(item, "cond");
    const line = lineOf(ctx.file.content, typeof item.start === "number" ? item.start : 0);
    if (!gProp) {
      unguarded += 1;
      if (unguarded === 2) {
        ctx.findings.push({
          id: `SC:overlap-unguarded:${ctx.file.rel}:${ctx.stateName}:${ctx.eventName}`, rule: "statechart-overlapping-guards",
          category: "structure", rung: "R1", severity: "error", soundness: "incorrectness-witness",
          file: ctx.file.rel, line,
          message: `State '${ctx.stateName}' on event '${ctx.eventName}' defines multiple unguarded transitions (non-deterministic dispatch).`,
          fix: "Give each competing branch a mutually exclusive guard or collapse to one deterministic transition.",
        });
      }
      continue;
    }
    const gVal = gProp.value;
    const gName = stringVal(gVal) ?? (isObj(gVal) && gVal.type === "Identifier" && typeof gVal.name === "string" ? gVal.name : "");
    if (gName && seenGuards.has(gName)) {
      ctx.findings.push({
        id: `SC:overlap-guard:${ctx.file.rel}:${ctx.stateName}:${ctx.eventName}:${gName}`, rule: "statechart-overlapping-guards",
        category: "structure", rung: "R1", severity: "error", soundness: "incorrectness-witness",
        file: ctx.file.rel, line,
        message: `State '${ctx.stateName}' on event '${ctx.eventName}' repeats overlapping guard '${gName}'.`,
        fix: "Ensure guard predicates on the same (state, event) pair are disjoint.",
      });
    }
    if (gName) seenGuards.add(gName);
  }
}

interface StatechartGraph {
  initialState: string;
  stateNames: Set<string>;
  stateLine: Map<string, number>;
  edges: Map<string, Set<string>>;
  nonTerminalOnEvents: Map<string, { events: Set<string>; line: number; hasWildcard: boolean }>;
}

function inspectInvokeProperty(
  ctx: { file: ScannedFile; stateName: string; findings: Finding[] },
  invObj: AstRec,
  targets: Set<string>,
): void {
  const onDone = getObjProp(invObj, "onDone");
  const onErr = getObjProp(invObj, "onError");
  if (onDone) extractTargetsFromTransition(onDone.value, targets);
  if (!onErr) return;
  const errTargets = new Set<string>();
  extractTargetsFromTransition(onErr.value, errTargets);
  for (const t of errTargets) {
    targets.add(t);
    if (!TERMINAL_OUTCOME_NAMES.has(t.toLowerCase())) continue;
    const errLine = lineOf(ctx.file.content, typeof onErr.start === "number" ? onErr.start : 0);
    ctx.findings.push({
      id: `SC:crash-terminal:${ctx.file.rel}:${errLine}`, rule: "sm-crash-folded-to-terminal",
      category: "structure", rung: "R0", severity: "error", soundness: "incorrectness-witness",
      file: ctx.file.rel, line: errLine,
      message: `State '${ctx.stateName}' folds unexpected invoke onError into terminal domain outcome '${t}' (uncomplect fence).`,
      fix: "Route unexpected infrastructure errors to a recoverable/pending/failed-system state instead of settling or refusing the domain outcome.",
    });
  }
}

function collectStatechartGraph(file: ScannedFile, initialState: string, stateProps: readonly AstRec[], findings: Finding[]): StatechartGraph {
  if (!initialState) throw new Error("initialState is required.");
  const graph: StatechartGraph = {
    initialState, stateNames: new Set(), stateLine: new Map(), edges: new Map(), nonTerminalOnEvents: new Map(),
  };
  for (const sp of stateProps) {
    const sName = propKeyName(sp);
    if (!sName || !isObj(sp.value) || sp.value.type !== "ObjectExpression") continue;
    graph.stateNames.add(sName);
    const sLine = lineOf(file.content, typeof sp.start === "number" ? sp.start : 0);
    graph.stateLine.set(sName, sLine);
    const targets = new Set<string>();
    graph.edges.set(sName, targets);
    const isFinal = stringVal(getObjProp(sp.value, "type")?.value) === "final";
    const onProp = getObjProp(sp.value, "on");
    const afterProp = getObjProp(sp.value, "after");
    const alwaysProp = getObjProp(sp.value, "always");
    const invokeProp = getObjProp(sp.value, "invoke");
    const entryProp = getObjProp(sp.value, "entry");
    const exitProp = getObjProp(sp.value, "exit");

    if (alwaysProp) extractTargetsFromTransition(alwaysProp.value, targets);
    if (afterProp && isObj(afterProp.value) && Array.isArray(afterProp.value.properties)) {
      for (const ap of afterProp.value.properties) if (isObj(ap)) extractTargetsFromTransition(ap.value, targets);
    }
    if (invokeProp && isObj(invokeProp.value)) inspectInvokeProperty({ file, stateName: sName, findings }, invokeProp.value, targets);
    const evSet = new Set<string>();
    let hasWildcard = Boolean(alwaysProp);
    if (onProp && isObj(onProp.value) && Array.isArray(onProp.value.properties)) {
      for (const ep of onProp.value.properties) {
        if (!isObj(ep) || ep.type !== "Property") continue;
        const evName = propKeyName(ep);
        if (!evName) continue;
        if (evName === "*") hasWildcard = true;
        evSet.add(evName);
        extractTargetsFromTransition(ep.value, targets);
        if (isObj(ep.value) && ep.value.type === "ArrayExpression" && Array.isArray(ep.value.elements)) {
          checkOverlappingTransitionGuards({ file, stateName: sName, eventName: evName, findings }, ep.value.elements);
        }
      }
    }
    if (!isFinal && evSet.size > 0) graph.nonTerminalOnEvents.set(sName, { events: evSet, line: sLine, hasWildcard });
    if (entryProp && !exitProp && (onProp || afterProp) && typeof entryProp.start === "number" && typeof entryProp.end === "number") {
      if (RESOURCE_ENTRY_HINT.test(file.content.slice(entryProp.start, entryProp.end))) {
        findings.push({
          id: `SC:missing-exit:${file.rel}:${sLine}`, rule: "statechart-missing-exit-cleanup",
          category: "structure", rung: "R1", severity: "warn", soundness: "hygiene-lint", file: file.rel, line: sLine,
          message: `State '${sName}' acquires a timer/subscription/resource in entry without a matching exit cleanup action.`,
          fix: "Add an explicit exit: cleanup action so interrupting transitions cannot leak resources.",
        });
      }
    }
  }
  return graph;
}

function auditStatechartGraph(file: ScannedFile, graph: StatechartGraph, findings: Finding[]): void {
  if (graph.stateNames.size === 0) return;
  const visited = new Set<string>();
  const queue = graph.stateNames.has(graph.initialState) ? [graph.initialState] : [];
  for (let head = 0; head < queue.length; head++) {
    const cur = queue[head];
    if (!cur || visited.has(cur)) continue;
    visited.add(cur);
    for (const next of graph.edges.get(cur) ?? []) if (graph.stateNames.has(next) && !visited.has(next)) queue.push(next);
  }
  for (const sName of graph.stateNames) {
    if (!visited.has(sName)) {
      findings.push({
        id: `SC:unreachable:${file.rel}:${sName}`, rule: "statechart-unreachable-state",
        category: "structure", rung: "R1", severity: "error", soundness: "incorrectness-witness",
        file: file.rel, line: graph.stateLine.get(sName) ?? 1,
        message: `State '${sName}' is unreachable from initial state '${graph.initialState}' (Harel statechart completeness).`,
        fix: `Wire a valid transition targeting '${sName}' or remove the dead state.`,
      });
    }
  }
  if (graph.nonTerminalOnEvents.size < 3) return;
  const evFreq = new Map<string, number>();
  for (const info of graph.nonTerminalOnEvents.values()) for (const ev of info.events) if (ev !== "*") evFreq.set(ev, (evFreq.get(ev) ?? 0) + 1);
  const sharedEvents = [...evFreq.entries()].filter(([, n]) => n >= 2 && n < graph.nonTerminalOnEvents.size).map(([ev]) => ev);
  for (const [sName, info] of graph.nonTerminalOnEvents.entries()) {
    if (info.hasWildcard) continue;
    const missing = sharedEvents.filter((ev) => !info.events.has(ev));
    if (missing.length > 0) {
      findings.push({
        id: `SC:unhandled:${file.rel}:${sName}:${missing[0]}`, rule: "statechart-unhandled-event",
        category: "structure", rung: "R1", severity: "warn", soundness: "hygiene-lint",
        file: file.rel, line: info.line,
        message: `Non-terminal state '${sName}' silently omits shared domain event(s): ${missing.join(", ")}.`,
        fix: `Handle ${missing.join(", ")} explicitly in '${sName}' (or declare an explicit reject/ignore transition).`,
      });
    }
  }
}

function inspectStatechartObject(file: ScannedFile, obj: AstRec, findings: Finding[]): void {
  const initProp = getObjProp(obj, "initial");
  const statesProp = getObjProp(obj, "states");
  const initialState = initProp ? stringVal(initProp.value) : null;
  if (!initialState || !statesProp || !isObj(statesProp.value) || statesProp.value.type !== "ObjectExpression") return;
  const stateProps = Array.isArray(statesProp.value.properties) ? statesProp.value.properties.filter((p): p is AstRec => isObj(p) && p.type === "Property") : [];
  if (stateProps.length < 2) return;
  const graph = collectStatechartGraph(file, initialState, stateProps, findings);
  auditStatechartGraph(file, graph, findings);
}

export function lintStatechartCompletenessAndCrashFolding(file: ScannedFile): Finding[] {
  if (file.language !== "typescript" && file.language !== "javascript") return [];
  const findings: Finding[] = [];
  const masked = maskCode(file.content, file.language, true);
  for (const m of masked.matchAll(/\bcatch\s*\([^)]*\)\s*\{[^}]{0,220}\b(?:status|state)\s*=\s*["']([a-zA-Z_]+)["']/g)) {
    const rawMatch = file.content.slice(m.index ?? 0, (m.index ?? 0) + m[0].length);
    const lit = /\b(?:status|state)\s*=\s*["']([a-zA-Z_]+)["']/.exec(rawMatch)?.[1] ?? "";
    if (!TERMINAL_OUTCOME_NAMES.has(lit.toLowerCase())) continue;
    const line = lineOf(file.content, m.index ?? 0);
    findings.push({
      id: `SC:catch-terminal:${file.rel}:${line}`, rule: "sm-crash-folded-to-terminal",
      category: "structure", rung: "R0", severity: "error", soundness: "incorrectness-witness",
      file: file.rel, line,
      message: `Catch block folds an unexpected exception into terminal domain outcome '${lit}' (uncomplect fence).`,
      fix: "Leave workflow pending or transition to an explicit infrastructure-error state instead of settling/refusing on crash.",
    });
  }
  if (!/\binitial\s*:/.test(masked) || !/\bstates\s*:/.test(masked)) return findings;
  let parsed: ReturnType<typeof parseSync>;
  try { parsed = parseSync(file.rel, file.content); } catch { return findings; }
  const stack: unknown[] = [parsed.program];
  let visited = 0;
  while (stack.length > 0 && visited < 40_000) {
    visited += 1;
    const cur = stack.pop();
    if (!isObj(cur)) continue;
    if (cur.type === "ObjectExpression") inspectStatechartObject(file, cur, findings);
    for (const v of Object.values(cur)) {
      if (Array.isArray(v)) for (const item of v) stack.push(item);
      else if (isObj(v)) stack.push(v);
    }
  }
  return findings;
}
