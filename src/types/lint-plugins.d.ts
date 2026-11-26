declare module "*/lint/index.mjs" {
  const plugin: {
    meta: { name: string };
    rules: Record<string, { create: (ctx: unknown) => Record<string, (node?: unknown) => void> }>;
  };
  export default plugin;
}

declare module "*/lint/oxlint-explicit-state-machine.mjs" {
  interface ExplicitSmVisitor {
    TSInterfaceDeclaration: (node?: unknown) => void;
    FunctionDeclaration: (node?: unknown) => void;
    "FunctionDeclaration:exit": (node?: unknown) => void;
    AssignmentExpression: (node?: unknown) => void;
    SwitchStatement: (node?: unknown) => void;
    "Program:exit": (node?: unknown) => void;
    [key: string]: (node?: unknown) => void;
  }

  const plugin: {
    meta: { name: string };
    rules: {
      "no-implicit-state-machine": {
        create: (ctx: unknown) => ExplicitSmVisitor;
      };
      [key: string]: {
        create: (ctx: unknown) => Record<string, (node?: unknown) => void>;
      };
    };
  };
  export default plugin;
}
