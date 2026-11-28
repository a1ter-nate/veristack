import assert from "node:assert/strict";
import { test } from "node:test";
import { createPluginHostSync } from "@veristack/core";
import { isVeristackPlugin } from "@veristack/plugin";
import { lawsFormalPlugin, runBoundedRelationalCheck } from "@veristack/plugin-laws-formal";

test("laws-formal plugin defines valid Veristack plugin and registers into commands", () => {
  assert.equal(isVeristackPlugin(lawsFormalPlugin), true);
  assert.equal(lawsFormalPlugin.id, "veristack.plugin.laws-formal");
  const host = createPluginHostSync({ includeBuiltins: false, plugins: [lawsFormalPlugin] });
  const statuses = host.list();
  assert.equal(statuses.length, 1);
  assert.equal(statuses[0]?.status, "active");
  assert.ok(host.registries.commands().length >= 1);
});

test("Jackson Small-Scope bounded relational model check finds privilege/tenant/terminal counterexamples and passes guarded models", () => {
  const broken = runBoundedRelationalCheck({
    schemaVersion: 1,
    name: "billing",
    roles: ["guest", "admin"],
    states: ["draft", "approved", "settled"],
    initialState: "draft",
    transitions: [
      { from: "draft", to: "approved", action: "approve" },
      { from: "settled", to: "draft", action: "reopen", crossTenant: true },
    ],
    invariants: [
      { id: "no-guest-approve", kind: "no-privilege-escalation", forbiddenTarget: "approved", privilegedRoles: ["admin"] },
      { id: "tenant-iso", kind: "tenant-isolation" },
      { id: "term-lock", kind: "terminal-immutability", terminalStates: ["settled"] },
    ],
  }, 4);
  assert.equal(broken.passed, false);
  assert.equal(broken.counterexamples.length, 3);
  assert.equal(broken.findings[0]?.rule, "bounded-relational-counterexample");

  const safe = runBoundedRelationalCheck({
    schemaVersion: 1,
    name: "billing-safe",
    roles: ["guest", "admin"],
    states: ["draft", "approved", "settled"],
    initialState: "draft",
    transitions: [
      { from: "draft", to: "approved", action: "approve", requiredRole: "admin" },
      { from: "approved", to: "settled", action: "settle", requiredRole: "admin" },
    ],
    invariants: [
      { id: "no-guest-approve", kind: "no-privilege-escalation", forbiddenTarget: "approved", privilegedRoles: ["admin"] },
      { id: "term-lock", kind: "terminal-immutability", terminalStates: ["settled"] },
      { id: "no-cycle", kind: "acyclic" },
    ],
  }, 4);
  assert.equal(safe.passed, true);
  assert.equal(safe.counterexamples.length, 0);
});
