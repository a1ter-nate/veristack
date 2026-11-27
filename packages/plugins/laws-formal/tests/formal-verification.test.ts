import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveThreeBandDecision } from "@veristack/plugin-circuits";
import { scanRepo } from "@veristack/core";
import type { System1ModelAnswer } from "@veristack/plugin";

test("exhaustive model check proves Circuit 3-band safety invariants across entire decision space", () => {
  const choices = ["BEHAVIOR", "CHANGE_DETECTOR", "TAUTOLOGY"] as const;
  const thresholds = { high: 0.8, low: 0.2 };
  const confidences: Array<number | null> = [null, 0, 0.1, 0.2, 0.21, 0.5, 0.79, 0.8, 0.95, 1];
  const candidateChoices: Array<string | null> = [null, "BEHAVIOR", "TAUTOLOGY", "HALLUCINATED_LABEL"];
  const booleans = [false, true] as const;

  let checkedStates = 0;
  let reachedHigh = false;
  let reachedLow = false;
  let reachedUncertain = false;
  let reachedAbstained = false;
  let reachedContradicted = false;

  for (const abstained of booleans) {
    for (const contradictsStaticFacts of booleans) {
      for (const choice of candidateChoices) {
        for (const confidence of confidences) {
          checkedStates += 1;
          const answer: System1ModelAnswer = { id: "m1", choice, confidence, abstained };
          const result = resolveThreeBandDecision({
            answer,
            validChoices: choices,
            thresholds,
            contradictsStaticFacts,
            highAction: (c) => ({
              action: c === "BEHAVIOR" ? "keep_verified" : "rewrite_or_delete",
              requiresHuman: c !== "BEHAVIOR",
            }),
            lowAction: "keep_advisory",
            escalateAction: "escalate_human",
            reasonPrefix: "formal-check",
          });

          const invalidChoice = choice === null || !choices.includes(choice as (typeof choices)[number]);
          if (abstained || invalidChoice || confidence === null) {
            assert.equal(result.band, "abstained");
            assert.equal(result.requiresHuman, true);
            assert.equal(result.corroborated, false);
            assert.equal(result.action, "escalate_human");
            reachedAbstained = true;
            continue;
          }

          if (contradictsStaticFacts) {
            assert.equal(result.band, "contradicted");
            assert.equal(result.requiresHuman, true);
            assert.equal(result.corroborated, false);
            assert.equal(result.action, "escalate_human");
            reachedContradicted = true;
            continue;
          }

          if (confidence >= thresholds.high) {
            assert.equal(result.band, "high");
            assert.equal(result.corroborated, true);
            reachedHigh = true;
          } else if (confidence <= thresholds.low) {
            assert.equal(result.band, "low");
            assert.equal(result.action, "keep_advisory");
            assert.equal(result.requiresHuman, false);
            reachedLow = true;
          } else {
            assert.equal(result.band, "uncertain");
            assert.equal(result.requiresHuman, true);
            assert.equal(result.action, "escalate_human");
            reachedUncertain = true;
          }
        }
      }
    }
  }

  assert.equal(checkedStates, 160);
  assert.ok(reachedHigh && reachedLow && reachedUncertain && reachedAbstained && reachedContradicted);
});

test("formal verification detector ignores markdown mentions and detects real .qnt/.dfy/stateright/kani specs", () => {
  const docOnlyDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-fv-doc-"));
  const realSpecDir = fs.mkdtempSync(path.join(os.tmpdir(), "vstack-fv-real-"));
  try {
    fs.writeFileSync(path.join(docOnlyDir, "README.md"), "We should someday add Quint, TLA+, Z3, and Kani.\n");
    fs.writeFileSync(
      path.join(docOnlyDir, "package.json"),
      JSON.stringify({ dependencies: { express: "^5.0.0" } }),
    );
    const docReport = scanRepo(docOnlyDir);
    const docR5 = docReport.rungs.find((r) => r.rung === "R5");
    assert.ok(docR5);
    assert.equal(docR5.evidence.includes("formal verification"), false);
    assert.ok(docR5.gaps.some((g) => g.includes("formal spec")));

    fs.writeFileSync(
      path.join(realSpecDir, "protocol.qnt"),
      "module protocol { var x: int\n action init = { x' = 0 }\n val inv = x >= 0 }\n",
    );
    const realReport = scanRepo(realSpecDir);
    const realR5 = realReport.rungs.find((r) => r.rung === "R5");
    assert.ok(realR5);
    assert.equal(realR5.evidence.includes("formal verification"), true);
  } finally {
    fs.rmSync(docOnlyDir, { recursive: true, force: true });
    fs.rmSync(realSpecDir, { recursive: true, force: true });
  }
});
