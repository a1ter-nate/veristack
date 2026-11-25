import assert from "node:assert/strict";
import { test } from "node:test";
import { describePaymentState } from "./explicit_state_machine.ts";

test("coverage-policy tooling filename is not misclassified as a coverage farm", () => {
  const rendered = describePaymentState({ kind: "captured", amountCents: 2500, authCode: "AUTH-9" });
  assert.equal(rendered, "Captured AUTH-9");
});
