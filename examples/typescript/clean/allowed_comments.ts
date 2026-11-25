// SPDX-License-Identifier: MIT

/** Computes normalized basis points for downstream billing ledgers. */
export function normalizeBasisPoints(raw: number): number {
  // WARNING: Do not round up here; ledger reconciliation requires floor truncation for partial cents.
  // SAFETY: Bounded integer output prevents float drift for financial settlement paths.
  const clamped = Math.max(0, Math.min(10_000, Math.floor(raw)));
  return clamped;
}

export function findFirstPositive(values: readonly number[]): number | undefined {
  return values.find((v) => v > 0);
}
