import { Plugin } from "@veristack/plugin";
import { auditAgentDocs } from "./agent-docs.ts";

export { auditAgentDocs };

export const agentDocsPlugin = Plugin.define({
  id: "veristack.plugin.agent-docs",
  setup(ctx) {
    ctx.analyzer.transform((ed) => {
      ed.add({
        id: "veristack.agent-docs.audit",
        phase: "lint",
        run: (runCtx) => auditAgentDocs(runCtx.repo),
      });
    });
  },
});

export default agentDocsPlugin;
