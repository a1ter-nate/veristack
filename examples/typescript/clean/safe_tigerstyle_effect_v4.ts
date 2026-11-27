import { Duration, Effect, Queue, Schedule, ServiceMap } from "effect";

const CONCURRENCY_MAX = 8;
const QUEUE_CAPACITY_MAX = 64;
const RETRY_COUNT_MAX = 3;

export const boundedWorkQueue = Queue.bounded<string>(QUEUE_CAPACITY_MAX);

export const processBatch = (items: readonly string[]) =>
  Effect.forEach(items, (item) => Effect.succeed(item), { concurrency: CONCURRENCY_MAX });

export const retryBounded = (eff: Effect.Effect<void, Error>) =>
  Effect.retry(
    eff,
    Schedule.intersect(Schedule.exponential(Duration.millis(50)), Schedule.recurs(RETRY_COUNT_MAX)),
  );

export const assertPositive = (count: number) =>
  count > 0 ? Effect.succeed(count) : Effect.dieMessage("count must be positive");

export class ClockService extends ServiceMap.Service<
  ClockService,
  {
    nowMs(): Effect.Effect<number>;
  }
>()("ClockService", {
  nowMs: () => Effect.succeed(0),
}) {}
