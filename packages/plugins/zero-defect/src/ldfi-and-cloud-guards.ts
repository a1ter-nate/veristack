import { lineOf, maskCode, type Finding, type ScannedFile } from "@veristack/plugin";

export interface FlowDependencySpec {
  id: string;
  ioDependencies: readonly string[];
  critical?: boolean;
}

export interface LdfiCutSet {
  faultedDependencies: string[];
  depth: number;
  impactedFlows: string[];
  blastRadius: number;
}

export function extractLdfiMinimalCutSets(
  flowsInput: readonly FlowDependencySpec[] | { flows?: readonly FlowDependencySpec[] },
  depthMax = 3,
): LdfiCutSet[] {
  const flows: readonly FlowDependencySpec[] = Array.isArray(flowsInput)
    ? flowsInput
    : ("flows" in flowsInput && Array.isArray(flowsInput.flows) ? flowsInput.flows : []);
  if (flows.length === 0) return [];
  const depthCap = Math.max(1, Math.min(3, Math.floor(depthMax)));
  const depToFlows = new Map<string, Set<string>>();
  for (const flow of flows) {
    if (!flow || !Array.isArray(flow.ioDependencies)) continue;
    for (const dep of flow.ioDependencies) {
      if (typeof dep !== "string" || !dep.trim()) continue;
      const set = depToFlows.get(dep.trim()) ?? new Set<string>();
      set.add(flow.id);
      depToFlows.set(dep.trim(), set);
    }
  }
  const deps = [...depToFlows.keys()].sort();
  const cutSets: LdfiCutSet[] = [];
  for (const d of deps) {
    const impacted = [...(depToFlows.get(d) ?? [])].sort();
    cutSets.push({ faultedDependencies: [d], depth: 1, impactedFlows: impacted, blastRadius: impacted.length });
  }
  if (depthCap >= 2) {
    for (let i = 0; i < deps.length; i++) {
      for (let j = i + 1; j < deps.length; j++) {
        const a = deps[i] ?? "";
        const b = deps[j] ?? "";
        const union = new Set<string>([...(depToFlows.get(a) ?? []), ...(depToFlows.get(b) ?? [])]);
        const maxSingle = Math.max(depToFlows.get(a)?.size ?? 0, depToFlows.get(b)?.size ?? 0);
        if (union.size > maxSingle) {
          cutSets.push({ faultedDependencies: [a, b], depth: 2, impactedFlows: [...union].sort(), blastRadius: union.size });
        }
      }
    }
  }
  return cutSets.sort((x, y) => y.blastRadius - x.blastRadius || x.depth - y.depth);
}

const NON_IDEMPOTENT_OP = /\b(?:charge|debit|transfer|withdraw|increment|append)\s*\(|\bINSERT\s+INTO\b/i;
const IDEMPOTENCY_GUARD = /\b(?:idempotency|idempotent|dedupe|dedup|alreadyProcessed|ON\s+CONFLICT|UPSERT|eventId|requestId)\b/i;
const PAGINATION_CALL = /\b(?:limit|pageSize|maxResults|per_page)\s*[:=]\s*(?:\d+|MAX_)/g;
const CURSOR_HANDLING = /\b(?:nextCursor|nextPageToken|hasMore|hasNextPage|continuationToken|truncated|next_page|cursor)\b/i;
const RPC_CALL_RE = /\b(?:grpc|rpcClient|connectClient)\s*\.\s*[a-zA-Z_$]\w*\s*\([^)]{0,160}\)/g;

export function analyzeGunawiCloudGuards(file: ScannedFile): Finding[] {
  if (!file.language || file.isTest || file.isStub) return [];
  if (file.language !== "typescript" && file.language !== "javascript") return [];
  const raw = file.content;
  const masked = maskCode(raw, file.language, true);
  const findings: Finding[] = [];

  for (const m of masked.matchAll(/\b(?:retry|recover|onRetry|handleRetry|replayEvent)\w*\s*\([^)]*\)\s*(?::[^{]+)?\{/g)) {
    const idx = m.index ?? 0;
    const body = raw.slice(idx, Math.min(raw.length, idx + 700));
    if (NON_IDEMPOTENT_OP.test(body) && !IDEMPOTENCY_GUARD.test(body)) {
      const line = lineOf(raw, idx);
      findings.push({
        id: `CLD:non-idemp:${file.rel}:${line}`, rule: "cloud-non-idempotent-recovery", category: "structure", rung: "R1",
        severity: "warn", soundness: "incorrectness-witness", file: file.rel, line,
        message: "Retry/recovery handler executes non-idempotent write/charge without an idempotency key or deduplication guard (Gunawi cloud bug class).",
        fix: "Pass a stable idempotencyKey or upsert/deduplicate on eventId before applying side effects.",
      });
    }
  }
  for (const m of masked.matchAll(PAGINATION_CALL)) {
    const idx = m.index ?? 0;
    const win = raw.slice(Math.max(0, idx - 120), Math.min(raw.length, idx + 420));
    if (/\.(?:items|rows|data|records)\b/.test(win) && /\b(?:list|query|fetch|find|search|select)\b/i.test(win) && !CURSOR_HANDLING.test(win)) {
      const line = lineOf(raw, idx);
      findings.push({
        id: `CLD:trunc:${file.rel}:${line}`, rule: "cloud-silent-limit-truncation", category: "structure", rung: "R1",
        severity: "warn", soundness: "incorrectness-witness", file: file.rel, line,
        message: "Paginated query/API read sets a fixed limit/pageSize without checking nextCursor/hasMore/truncated (silent truncation risk).",
        fix: "Loop over nextCursor/nextPageToken (with an explicit page cap) or fail loudly if results are truncated.",
      });
      break;
    }
  }
  for (const m of masked.matchAll(RPC_CALL_RE)) {
    const idx = m.index ?? 0;
    const callText = raw.slice(idx, idx + m[0].length);
    if (!/\b(?:deadline|timeout|signal|AbortSignal)\b/i.test(callText)) {
      const line = lineOf(raw, idx);
      findings.push({
        id: `CLD:rpc-timeout:${file.rel}:${line}`, rule: "cloud-rpc-missing-timeout", category: "structure", rung: "R1",
        severity: "warn", soundness: "incorrectness-witness", file: file.rel, line,
        message: "RPC client invocation omits explicit deadline/timeout/AbortSignal.",
        fix: "Pass an explicit deadline or { signal: AbortSignal.timeout(ms) } on every RPC boundary.",
      });
    }
  }
  return findings;
}
