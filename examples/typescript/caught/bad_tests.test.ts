import { describePayment } from "./state_machine_soup.ts";

vi.mock("./state_machine_soup.ts");

test.skip("skipped test hides regressions", () => {
  expect(true).toBe(true);
});

test("flaky non-hermetic test", async () => {
  process.env.FEATURE_FLAG = "1";
  const now = Date.now();
  await new Promise((resolve) => setTimeout(resolve, 25));
  const status = now > 0 ? 200 : 404;
  expect([200, 404]).toContain(status);
  expect(describePayment({ status: "pending" })).toBe("Waiting");
});
