export type PaymentState =
  | { readonly kind: "pending"; readonly amountCents: number }
  | { readonly kind: "captured"; readonly amountCents: number; readonly authCode: string }
  | { readonly kind: "failed"; readonly reason: string };

function assertNever(value: never): never {
  throw new Error(`Unhandled payment state: ${JSON.stringify(value)}`);
}

export function describePaymentState(state: PaymentState): string {
  switch (state.kind) {
    case "pending":
      return `Pending ${state.amountCents}`;
    case "captured":
      return `Captured ${state.authCode}`;
    case "failed":
      return `Failed: ${state.reason}`;
    default:
      return assertNever(state);
  }
}
