import { Effect, Layer, ManagedRuntime, Queue, Schedule, ServiceMap } from "effect";

class InvariantError extends Error {}

export const unboundedQ = Queue.unbounded<string>();

export const unboundedForEach = (items: readonly string[]) =>
  Effect.forEach(items, (item) => Effect.succeed(item), { concurrency: "unbounded" });

export const uncappedRetry = (eff: Effect.Effect<void, Error>) =>
  Effect.retry(eff, Schedule.exponential("100 millis"));

export const invariantAsTypedError = (ok: boolean) =>
  ok ? Effect.void : Effect.fail(new InvariantError("broken state"));

export const allocInLoop = (items: readonly string[]) =>
  Effect.forEach(items, () => Effect.sync(() => ManagedRuntime.make(Layer.empty)), { concurrency: 4 });

export class OversizedService extends ServiceMap.Service<
  OversizedService,
  {
    op1(): void;
    op2(): void;
    op3(): void;
    op4(): void;
    op5(): void;
    op6(): void;
    op7(): void;
    op8(): void;
    op9(): void;
  }
>()("OversizedService", {
  op1: () => {},
  op2: () => {},
  op3: () => {},
  op4: () => {},
  op5: () => {},
  op6: () => {},
  op7: () => {},
  op8: () => {},
  op9: () => {},
}) {}
