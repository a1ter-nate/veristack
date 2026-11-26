import assert from "node:assert/strict";
import test from "node:test";
import fc from "fast-check";
import { lintNoComments } from "../../src/no-comments.ts";
import { buildRatchetBaseline, evaluateRatchet, type RatchetBaseline } from "../../src/ratchet.ts";
import { computeCrapScore, reportParsers } from "../../src/rungs/reports.ts";
import { parseGitHubWorkflow } from "../../src/rungs/workflow-audit.ts";
import type { Finding, RungStatus } from "../../src/types.ts";

const { parseCoberturaXml, parseJunitOrTrx, parseLcov, parseStrykerJson } = reportParsers;

function makeFinding(rule: string, idx: number, file = "src/a.ts", severity: Finding["severity"] = "error"): Finding {
  return {
    id: `F:${rule}:${file}:${idx}`,
    rule,
    category: "cheat",
    rung: "R0",
    severity,
    file,
    line: idx + 1,
    message: "m",
    fix: "f",
  };
}

function makeRung(
  rung: RungStatus["rung"],
  grade: RungStatus["coverageGrade"],
  score: number,
  executedInCi: boolean,
): RungStatus {
  return {
    rung,
    name: rung,
    speedBudget: "< 2s",
    targetBudget: "100%",
    status:
      grade === "well-covered"
        ? "covered"
        : grade === "poorly-covered"
          ? "partial"
          : grade === "not-applicable"
            ? "not-applicable"
            : "hole",
    coverageGrade: grade,
    coverageScore: score,
    executedInCi,
    receiptVerified: executedInCi,
    idealCoverage: "ideal",
    observedCoverage: "actual",
    checks: [],
    observedCount: 1,
    evidence: grade === "not-covered" ? [] : ["ev"],
    gaps: [],
  };
}

interface RatchetModel {
  counts: Record<string, number>;
  r2Score: number;
}

interface RatchetSut {
  baseline: RatchetBaseline;
  rungs: RungStatus[];
}

function buildFindings(counts: Record<string, number>): Finding[] {
  return Object.entries(counts).flatMap(([rule, count]) =>
    Array.from({ length: count }, (_, idx) => makeFinding(rule, idx)),
  );
}

class RegressRuleCommand implements fc.Command<RatchetModel, RatchetSut> {
  readonly rule: string;
  constructor(rule: string) {
    this.rule = rule;
  }
  check(): boolean {
    return true;
  }
  run(m: RatchetModel, s: RatchetSut): void {
    const nextCounts = { ...m.counts, [this.rule]: (m.counts[this.rule] ?? 0) + 1 };
    const evalRes = evaluateRatchet(buildFindings(nextCounts), s.baseline, s.rungs);
    assert.equal(evalRes.passed, false);
    assert.ok(evalRes.regressions.some((r) => r.rule === this.rule));
  }
  toString(): string {
    return `Regress(${this.rule})`;
  }
}

class TightenRuleCommand implements fc.Command<RatchetModel, RatchetSut> {
  readonly rule: string;
  constructor(rule: string) {
    this.rule = rule;
  }
  check(m: Readonly<RatchetModel>): boolean {
    return (m.counts[this.rule] ?? 0) > 0;
  }
  run(m: RatchetModel, s: RatchetSut): void {
    m.counts[this.rule] = (m.counts[this.rule] ?? 1) - 1;
    const findings = buildFindings(m.counts);
    const beforeTighten = evaluateRatchet(findings, s.baseline, s.rungs);
    assert.equal(beforeTighten.passed, false);
    assert.ok(beforeTighten.tightenAvailable.some((t) => t.rule === this.rule));
    s.baseline = buildRatchetBaseline(findings, s.rungs);
    assert.equal(s.baseline.rules[this.rule] ?? 0, m.counts[this.rule]);
  }
  toString(): string {
    return `Tighten(${this.rule})`;
  }
}

class ImproveR2ScoreCommand implements fc.Command<RatchetModel, RatchetSut> {
  check(m: Readonly<RatchetModel>): boolean {
    return m.r2Score < 95;
  }
  run(m: RatchetModel, s: RatchetSut): void {
    m.r2Score = Math.min(100, m.r2Score + 10);
    const nextGrade = m.r2Score >= 80 ? "well-covered" : "poorly-covered";
    s.rungs = s.rungs.map((r) => (r.rung === "R2" ? makeRung("R2", nextGrade, m.r2Score, true) : r));
    s.baseline = buildRatchetBaseline(buildFindings(m.counts), s.rungs);
    const dropped = s.rungs.map((r) =>
      r.rung === "R2" ? makeRung("R2", nextGrade, Math.max(0, m.r2Score - 5), true) : r,
    );
    const dropRes = evaluateRatchet(buildFindings(m.counts), s.baseline, dropped);
    assert.equal(dropRes.passed, false);
    assert.ok(dropRes.rungRegressions.some((rr) => rr.rung === "R2"));
  }
  toString(): string {
    return "ImproveAndGuardR2Score";
  }
}

test("fast-check PBT: lintNoComments produces 0 FPs on arbitrary safe string literals and catches prose comments", () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 1, maxLength: 24 }).filter((s) => !/["'\\`\r\n]/.test(s)),
      fc.string({ minLength: 3, maxLength: 20 }).filter((s) => /^[a-z][a-z ]+[a-z]$/.test(s)),
      (urlPart, prose) => {
        const clean = `export const u = "https://example.com/${urlPart}";\n`;
        assert.deepEqual(lintNoComments("src/gen.ts", clean, "typescript"), []);

        const dirty = `// ${prose}\n${clean}`;
        const hits = lintNoComments("src/gen.ts", dirty, "typescript");
        assert.equal(hits.length, 1);
        assert.equal(hits[0]?.rule, "no-comments");
      },
    ),
    { numRuns: 50 },
  );
});

test("fast-check PBT: CRAP score is strictly monotonic in complexity and non-increasing with coverage", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 25 }),
      fc.integer({ min: 1, max: 15 }),
      fc.double({ min: 0, max: 0.9, noNaN: true }),
      fc.double({ min: 0.01, max: 0.1, noNaN: true }),
      (cc1, deltaCc, cov1, deltaCov) => {
        const cc2 = cc1 + deltaCc;
        const cov2 = Math.min(1, cov1 + deltaCov);
        assert.ok(computeCrapScore(cc2, cov1) > computeCrapScore(cc1, cov1));
        assert.ok(computeCrapScore(cc1, cov2) <= computeCrapScore(cc1, cov1));
        assert.equal(computeCrapScore(cc1, 1), cc1);
        assert.equal(computeCrapScore(cc1, 0), cc1 * cc1 + cc1);
      },
    ),
    { numRuns: 60 },
  );
});

test("fast-check stateful MBT: ratchet monotonicity, score-drop detection, and tightening hold under fc.commands", () => {
  const cmds = [
    fc.constantFrom("rA", "rB", "rC").map((r) => new RegressRuleCommand(r)),
    fc.constantFrom("rA", "rB", "rC").map((r) => new TightenRuleCommand(r)),
    fc.constant(new ImproveR2ScoreCommand()),
  ];
  fc.assert(
    fc.property(fc.commands(cmds, { maxCommands: 20 }), (seq) => {
      const initCounts = { rA: 3, rB: 2, rC: 2 };
      const initRungs = [makeRung("R0", "well-covered", 100, true), makeRung("R2", "poorly-covered", 60, true)];
      const model: RatchetModel = { counts: { ...initCounts }, r2Score: 60 };
      const sut: RatchetSut = {
        baseline: buildRatchetBaseline(buildFindings(initCounts), initRungs),
        rungs: initRungs,
      };
      fc.modelRun(() => ({ model, real: sut }), seq);
    }),
    { numRuns: 40 },
  );
});

test("parseGitHubWorkflow preserves quoted # tokens and strips column-0 and inline YAML comments", () => {
  const wf = [
    "# column-0 comment",
    "name: Real CI",
    "on: [pull_request]",
    "jobs:",
    "  verify:",
    "    steps:",
    '      - run: bun test --grep "case#1 \\"quoted\\"" # inline comment',
    "      - run: oxlint . # trailing oxlint comment",
  ].join("\n");
  const parsed = parseGitHubWorkflow({
    rel: ".github/workflows/real.yml",
    abs: "/virtual/.github/workflows/real.yml",
    isTest: false,
    isWorkflow: true,
    content: wf,
    lines: 8,
  });
  assert.equal(parsed.isPrBlocking, true);
  assert.deepEqual(parsed.activeCommands, ['bun test --grep "case#1 \\"quoted\\""', "oxlint ."]);
});

test("structured report adapters aggregate multi-suite JUnit, reversed Cobertura, TRX errors, and LCOV summaries", () => {
  const lcov = parseLcov("SF:src/a.ts\nLF:20\nLH:0\nend_of_record\nSF:src/b.ts\nDA:1,1\nDA:2,0\nend_of_record\n");
  assert.equal(lcov.get("src/a.ts"), 0);
  assert.equal(lcov.get("src/b.ts"), 0.5);

  const cob = parseCoberturaXml(
    '<coverage><class line-rate="0.0" filename="src/b.cs"/><class line-rate="1.0" filename="src/b.cs"/></coverage>',
  );
  assert.equal(cob.get("src/b.cs"), 0);

  const stryker = parseStrykerJson(
    JSON.stringify({
      files: {
        "src/a.ts": {
          mutants: [{ status: "Killed" }, { status: "Timeout" }, { status: "Survived" }, { status: "CompileError" }],
        },
      },
    }),
  );
  assert.equal(stryker, 66.67);

  const junit = parseJunitOrTrx(
    '<testsuites><testsuite name="a" tests="5" failures="0"/><testsuite name="b" tests="3" failures="2" errors="1"/></testsuites>',
  );
  assert.deepEqual(junit, { passed: 5, failed: 3, skipped: 0 });

  const trx = parseJunitOrTrx('<ResultSummary><Counters passed="10" failed="1" error="1" total="12" /></ResultSummary>');
  assert.deepEqual(trx, { passed: 10, failed: 2, skipped: 0 });
});
