import { createHash } from "node:crypto";
import { runSystem1Provider, type System1ProviderOptions } from "../system1-providers.ts";
import type {
  CircuitBand,
  CircuitReceipt,
  CircuitRunReport,
  CircuitThresholds,
  System1ModelAnswer,
  System1Request,
  System1RubricId,
} from "../types.ts";

export interface System1DecisionEngine {
  readonly name: string;
  decide(requests: readonly System1Request[]): Promise<System1ModelAnswer[]>;
}

export interface ShortCircuitDecision {
  action: string;
  reason: string;
  requiresHuman: boolean;
}

export interface ThreeBandResolutionInput {
  answer: System1ModelAnswer | undefined;
  validChoices: readonly string[];
  thresholds: CircuitThresholds;
  contradictsStaticFacts: boolean;
  highAction: (choice: string) => { action: string; requiresHuman: boolean };
  lowAction: string;
  escalateAction: string;
  reasonPrefix: string;
}

export interface ResolvedDecision {
  band: CircuitBand;
  action: string;
  reason: string;
  requiresHuman: boolean;
  corroborated: boolean;
}

export interface CircuitDefinition<TInput, TFacts> {
  readonly id: string;
  readonly version: string;
  readonly title: string;
  readonly description: string;
  readonly rubricId: System1RubricId;
  readonly choices: readonly string[];
  readonly thresholds: CircuitThresholds;
  readonly itemId: (input: TInput, index: number) => string;
  readonly subject: (input: TInput) => string;
  readonly extractFacts: (input: TInput) => TFacts;
  readonly summarizeFacts: (facts: TFacts) => string;
  readonly shortCircuit: (facts: TFacts) => ShortCircuitDecision | null;
  readonly buildRequest: (input: TInput, facts: TFacts, requestId: string) => System1Request;
  readonly resolve: (facts: TFacts, answer: System1ModelAnswer | undefined) => ResolvedDecision;
}

export function createSystem1Engine(options: System1ProviderOptions): System1DecisionEngine {
  const label = options.model ? `${options.provider}:${options.model}` : options.provider;
  return {
    name: label,
    decide: (requests) => runSystem1Provider(requests, options),
  };
}

export function resolveThreeBandDecision(input: ThreeBandResolutionInput): ResolvedDecision {
  const { answer, validChoices, thresholds, contradictsStaticFacts, highAction, lowAction, escalateAction, reasonPrefix } = input;

  if (!answer || answer.abstained || !answer.choice || !validChoices.includes(answer.choice) || answer.confidence === null) {
    return {
      band: "abstained",
      action: escalateAction,
      reason: `${reasonPrefix}: System 1 abstained or returned invalid choice; escalating to human.`,
      requiresHuman: true,
      corroborated: false,
    };
  }

  if (contradictsStaticFacts) {
    return {
      band: "contradicted",
      action: escalateAction,
      reason: `${reasonPrefix}: System 1 choice "${answer.choice}" contradicts verified static facts; escalating to human.`,
      requiresHuman: true,
      corroborated: false,
    };
  }

  if (answer.confidence >= thresholds.high) {
    const mapped = highAction(answer.choice);
    return {
      band: "high",
      action: mapped.action,
      reason: `${reasonPrefix}: high-confidence corroborated "${answer.choice}" (p=${answer.confidence.toFixed(2)} >= ${thresholds.high.toFixed(2)}).`,
      requiresHuman: mapped.requiresHuman,
      corroborated: true,
    };
  }

  if (answer.confidence <= thresholds.low) {
    return {
      band: "low",
      action: lowAction,
      reason: `${reasonPrefix}: low-confidence signal (p=${answer.confidence.toFixed(2)} <= ${thresholds.low.toFixed(2)}); applying safe default.`,
      requiresHuman: false,
      corroborated: true,
    };
  }

  return {
    band: "uncertain",
    action: escalateAction,
    reason: `${reasonPrefix}: mid-band uncertainty (p=${answer.confidence.toFixed(2)} in (${thresholds.low.toFixed(2)}, ${thresholds.high.toFixed(2)})); escalating to human.`,
    requiresHuman: true,
    corroborated: true,
  };
}

interface StagedItem<TFacts> {
  itemId: string;
  subject: string;
  facts: TFacts;
  staticSummary: string;
  shortDecision: ShortCircuitDecision | null;
  requestId?: string;
}

function hashCircuitDefinition<TInput, TFacts>(circuit: CircuitDefinition<TInput, TFacts>): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        id: circuit.id,
        version: circuit.version,
        rubricId: circuit.rubricId,
        choices: circuit.choices,
        thresholds: circuit.thresholds,
      }),
    )
    .digest("hex")
    .slice(0, 16);
}

function resolveStagedReceipts<TInput, TFacts>(
  circuit: CircuitDefinition<TInput, TFacts>,
  staged: readonly StagedItem<TFacts>[],
  answerById: ReadonlyMap<string, System1ModelAnswer>,
): { receipts: CircuitReceipt[]; bandCounts: Record<CircuitBand, number> } {
  const bandCounts: Record<CircuitBand, number> = {
    short_circuit: 0,
    high: 0,
    uncertain: 0,
    low: 0,
    abstained: 0,
    contradicted: 0,
  };
  const receipts: CircuitReceipt[] = [];
  if (!circuit.id) throw new Error("Circuit id is required.");
  if (!staged.length) return { receipts, bandCounts };

  for (const row of staged) {
    if (row.shortDecision) {
      bandCounts.short_circuit += 1;
      receipts.push({
        itemId: row.itemId,
        subject: row.subject,
        shortCircuited: true,
        band: "short_circuit",
        action: row.shortDecision.action,
        reason: row.shortDecision.reason,
        requiresHuman: row.shortDecision.requiresHuman,
        corroborated: true,
        staticSummary: row.staticSummary,
        modelChoice: null,
        modelConfidence: null,
      });
      continue;
    }

    const answer = row.requestId ? answerById.get(row.requestId) : undefined;
    const resolved = circuit.resolve(row.facts, answer);
    bandCounts[resolved.band] += 1;
    receipts.push({
      itemId: row.itemId,
      subject: row.subject,
      shortCircuited: false,
      band: resolved.band,
      action: resolved.action,
      reason: resolved.reason,
      requiresHuman: resolved.requiresHuman,
      corroborated: resolved.corroborated,
      staticSummary: row.staticSummary,
      modelChoice: answer?.choice ?? null,
      modelConfidence: answer?.confidence ?? null,
    });
  }
  return { receipts, bandCounts };
}

export async function runCircuit<TInput, TFacts>(
  circuit: CircuitDefinition<TInput, TFacts>,
  inputs: readonly TInput[],
  engine: System1DecisionEngine,
): Promise<CircuitRunReport> {
  if (!circuit.id) throw new Error("Circuit id is required.");
  if (!engine.name) throw new Error("Decision engine name is required.");

  const circuitHash = hashCircuitDefinition(circuit);
  const staged: StagedItem<TFacts>[] = [];
  const pendingRequests: System1Request[] = [];

  for (const [i, item] of inputs.entries()) {
    const itemId = circuit.itemId(item, i);
    const subject = circuit.subject(item);
    const facts = circuit.extractFacts(item);
    const staticSummary = circuit.summarizeFacts(facts);
    const shortDecision = circuit.shortCircuit(facts);

    if (shortDecision) {
      staged.push({ itemId, subject, facts, staticSummary, shortDecision });
    } else {
      const requestId = `${circuit.id}:${itemId}`;
      pendingRequests.push(circuit.buildRequest(item, facts, requestId));
      staged.push({ itemId, subject, facts, staticSummary, shortDecision: null, requestId });
    }
  }

  const answers = pendingRequests.length > 0 ? await engine.decide(pendingRequests) : [];
  const answerById = new Map(answers.map((a) => [a.id, a]));
  const { receipts, bandCounts } = resolveStagedReceipts(circuit, staged, answerById);

  const totalInputs = inputs.length;
  const shortCircuitedCount = bandCounts.short_circuit;
  const modelCalledCount = totalInputs - shortCircuitedCount;
  const shortCircuitRate = totalInputs === 0 ? 1 : Number((shortCircuitedCount / totalInputs).toFixed(4));

  return {
    schemaVersion: 1,
    circuitId: circuit.id,
    circuitVersion: circuit.version,
    circuitHash,
    provider: engine.name,
    thresholds: circuit.thresholds,
    totalInputs,
    shortCircuitedCount,
    modelCalledCount,
    shortCircuitRate,
    bandCounts,
    receipts,
  };
}
