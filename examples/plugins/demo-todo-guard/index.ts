import { lineOf, Plugin, type Finding } from "@veristack/plugin";

const FIXME_MARKER = /\bFIXME_BLOCKER\b/g;

export const demoTodoGuardPlugin = Plugin.define({
  id: "demo.plugin.todo-guard",
  setup(ctx) {
    ctx.language.transform((ed) => {
      ed.add({
        id: "demo-dsl",
        extensions: [".vdsl"],
      });
    });

    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "demo.todo-guard.analyzer",
        phase: "lint",
        run(runCtx) {
          const findings: Finding[] = [];
          for (const file of runCtx.repo.files) {
            if (file.isTest) continue;
            for (const match of file.content.matchAll(FIXME_MARKER)) {
              const line = lineOf(file.content, match.index ?? 0);
              findings.push({
                id: `DEMO:todo-guard:${file.rel}:${line}`,
                rule: "demo-todo-guard",
                category: "structure",
                rung: "R0",
                severity: "warn",
                file: file.rel,
                line,
                message: "Unresolved FIXME_BLOCKER marker flagged by demo.plugin.todo-guard.",
                fix: "Resolve the FIXME_BLOCKER item or remove the marker before merging.",
              });
            }
          }
          return findings;
        },
      });
    });

    ctx.command.transform((ed) => {
      ed.add({
        id: "demo.cmd.todo-status",
        name: "demo-status",
        usage: "vstack demo-status [--json]",
        run(cmdCtx) {
          const payload = { plugin: "demo.plugin.todo-guard", active: true, language: "demo-dsl" };
          console.log(cmdCtx.asJson ? JSON.stringify(payload, null, 2) : "demo.plugin.todo-guard: ACTIVE (language=demo-dsl, rule=demo-todo-guard)");
          return 0;
        },
      });
    });
  },
});

export default demoTodoGuardPlugin;
