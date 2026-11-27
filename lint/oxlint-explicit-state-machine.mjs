const LIFECYCLE_BOOL_NAME =
  /^(?:is(?:Running|Armed|Stopped|Draining|Loading|Error|Errored|Pending|Complete|Completed|Closed|Cancelled|Canceled|Connected|Disconnected|Paused|Ready|Open|Opened|Idle|Active|Busy|Starting|Stopping|Retrying|Failed|Succeeded|Aborted|Expired|Reverted|Locked|Unlocked|Initialized|Disposed|Healthy|Degraded)|has(?:Started|Failed|Finished|Completed|Closed|Cancelled|Canceled|Errored|Connected|TimedOut|Expired|Reverted|Stopped|Succeeded)|was(?:Reverted|Cancelled|Canceled|Stopped|Closed|Aborted|Failed|Started)|aborted|armed|draining|saturated|stopping|starting|reverted|expired|active|running|stopped|loading|pending|closed|cancelled|canceled|connected|paused|completed|failed|disposed)$/i;

const STATE_DISCRIMINANT = new Set(["status", "state", "phase", "stage", "mode"]);
const MUTABLE_STATE_PROP = new Set(["status", "state", "phase", "stage"]);
const SWITCH_STATE_PROP = new Set(["status", "state", "phase", "stage", "kind"]);
const CONFIG_TYPE_SUFFIX = /(?:Options|Config|Settings|Flags|Args|Params|Props|Input|Query|Filter)$/;
const CANONICAL_TRANSITION_FN = /^(?:transition|reduce|reducer|applyEvent|nextState|stepState|handleEvent)$/i;
const EXHAUSTIVE_CALLEE = /^(?:assertNever|exhaustiveCheck|unreachable)$/;

function keyName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  return null;
}

function unwrapTypeAnnotation(typeNode) {
  let cur = typeNode;
  for (let i = 0; i < 8 && cur && cur.type === "TSTypeAnnotation"; i++) {
    cur = cur.typeAnnotation;
  }
  return cur;
}

function isBooleanTypeAnnotation(typeNode) {
  const cur = unwrapTypeAnnotation(typeNode);
  return Boolean(cur && cur.type === "TSBooleanKeyword");
}

function isBooleanLiteralInit(init) {
  return Boolean(init && init.type === "Literal" && typeof init.value === "boolean");
}

function isStringLiteralUnion(typeNode) {
  const cur = unwrapTypeAnnotation(typeNode);
  if (!cur || cur.type !== "TSUnionType" || !Array.isArray(cur.types) || cur.types.length < 2) {
    return false;
  }
  const literalCount = cur.types.filter(
    (t) => t && t.type === "TSLiteralType" && t.literal && typeof t.literal.value === "string",
  ).length;
  return literalCount >= 2;
}

function isStateDiscriminantExpr(node) {
  if (!node) return false;
  if (node.type === "Identifier") return SWITCH_STATE_PROP.has(node.name);
  if (node.type === "MemberExpression" && !node.computed) {
    const prop = keyName(node.property);
    return prop !== null && SWITCH_STATE_PROP.has(prop);
  }
  return false;
}

function containsNeverOrExhaustive(root) {
  if (!root || typeof root !== "object") return false;
  const stack = [root];
  let visited = 0;
  while (stack.length > 0 && visited < 4_000) {
    visited += 1;
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    if (node.type === "TSNeverKeyword") return true;
    if (node.type === "CallExpression") {
      const calleeName = keyName(node.callee) ?? (node.callee?.type === "MemberExpression" ? keyName(node.callee.property) : null);
      if (calleeName && EXHAUSTIVE_CALLEE.test(calleeName)) return true;
    }
    for (const key of Object.keys(node)) {
      if (key === "parent" || key === "loc" || key === "range") continue;
      const val = node[key];
      if (Array.isArray(val)) for (const child of val) stack.push(child);
      else if (val && typeof val === "object" && val.type) stack.push(val);
    }
  }
  return false;
}

function checkMembers(context, spec) {
  if (!spec) return;
  if (!Array.isArray(spec.members)) return;
  const { reportNode, kind, typeName, members, checkOptionalBag } = spec;
  const lifecycleBools = [];
  let hasDiscriminantUnion = false;
  let discriminantName = "";
  const optionalSiblings = [];

  for (const member of members) {
    if (!member) continue;
    if (member.type !== "TSPropertySignature" && member.type !== "PropertyDefinition") continue;
    const name = keyName(member.key);
    if (!name) continue;

    if (
      (isBooleanTypeAnnotation(member.typeAnnotation) || isBooleanLiteralInit(member.value)) &&
      LIFECYCLE_BOOL_NAME.test(name)
    ) {
      lifecycleBools.push(name);
    }

    if (checkOptionalBag && member.type === "TSPropertySignature") {
      if (!member.optional && STATE_DISCRIMINANT.has(name) && isStringLiteralUnion(member.typeAnnotation)) {
        if (!(name === "mode" && CONFIG_TYPE_SUFFIX.test(typeName))) {
          hasDiscriminantUnion = true;
          discriminantName = name;
        }
      } else if (member.optional) {
        optionalSiblings.push(name);
      }
    }
  }

  if (lifecycleBools.length >= 3) {
    context.report({
      node: reportNode,
      messageId: "booleanSoup",
      data: {
        kind,
        name: typeName,
        count: String(lifecycleBools.length),
        states: String(2 ** lifecycleBools.length),
        fields: lifecycleBools.slice(0, 5).join(", "),
      },
    });
  }

  if (checkOptionalBag && hasDiscriminantUnion && optionalSiblings.length >= 2) {
    context.report({
      node: reportNode,
      messageId: "optionalBag",
      data: {
        kind,
        name: typeName,
        discriminant: discriminantName,
        count: String(optionalSiblings.length),
        fields: optionalSiblings.slice(0, 5).join(", "),
      },
    });
  }
}

function resolveFnNodeName(node) {
  if (node.id && node.id.type === "Identifier") return node.id.name;
  if (node.parent) {
    if (node.parent.type === "MethodDefinition") return keyName(node.parent.key);
    if (node.parent.type === "Property") return keyName(node.parent.key);
    if (node.parent.type === "VariableDeclarator") return keyName(node.parent.id);
  }
  return null;
}

function enclosingFunctionName(stack) {
  for (let i = stack.length - 1; i >= 0; i--) {
    const fn = stack[i];
    if (fn) return fn;
  }
  return null;
}

const noImplicitStateMachineRule = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow implicit state machines: boolean-flag lifecycle soup, optional-field state bags, scattered state mutations, and non-exhaustive state switches.",
    },
    schema: [],
    messages: {
      booleanSoup:
        "{{kind}} {{name}} declares {{count}} lifecycle boolean flags ({{fields}}) admitting {{states}} states. Collapse into a discriminated union ({ readonly kind: ... }) with an explicit transition table.",
      optionalBag:
        '{{kind}} {{name}} pairs literal-union "{{discriminant}}" with {{count}} optional payload fields ({{fields}}). Split into a discriminated union where each variant holds only its valid fields.',
      scatteredMutation:
        "Direct state mutation scattered across {{count}} functions/methods ({{names}}). Centralize transitions in one pure transition(state, event) function validated against an explicit ALLOWED_TRANSITIONS table.",
      nonExhaustiveSwitch:
        "switch on state discriminant lacks an exhaustiveness guard (never / assertNever) in default. Add const _exhaustive: never = state so new states fail at compile time.",
    },
  },
  create(context) {
    const fnStack = [];
    const mutatingFns = new Map();
    const pushFn = (node) => fnStack.push(resolveFnNodeName(node) ?? "<anonymous>");
    const popFn = () => { fnStack.pop(); };
    return {
      TSInterfaceDeclaration(node) {
        checkMembers(context, { reportNode: node, kind: "interface", typeName: node.id?.name ?? "Anonymous", members: node.body?.body ?? [], checkOptionalBag: true });
      },
      TSTypeAliasDeclaration(node) {
        if (node.typeAnnotation?.type === "TSTypeLiteral") {
          checkMembers(context, { reportNode: node, kind: "type", typeName: node.id?.name ?? "Anonymous", members: node.typeAnnotation.members ?? [], checkOptionalBag: true });
        }
      },
      ClassDeclaration(node) {
        checkMembers(context, { reportNode: node, kind: "class", typeName: node.id?.name ?? "AnonymousClass", members: node.body?.body ?? [], checkOptionalBag: false });
      },
      ClassExpression(node) {
        checkMembers(context, { reportNode: node, kind: "class", typeName: node.id?.name ?? "AnonymousClass", members: node.body?.body ?? [], checkOptionalBag: false });
      },
      FunctionDeclaration: pushFn,
      "FunctionDeclaration:exit": popFn,
      FunctionExpression: pushFn,
      "FunctionExpression:exit": popFn,
      ArrowFunctionExpression: pushFn,
      "ArrowFunctionExpression:exit": popFn,
      AssignmentExpression(node) {
        if (node.operator !== "=" || node.left?.type !== "MemberExpression" || node.left.computed) return;
        const prop = keyName(node.left.property);
        if (!prop || !MUTABLE_STATE_PROP.has(prop)) return;
        const fnName = enclosingFunctionName(fnStack);
        if (!fnName || fnName === "constructor" || CANONICAL_TRANSITION_FN.test(fnName)) return;
        if (!mutatingFns.has(fnName)) mutatingFns.set(fnName, node);
      },
      SwitchStatement(node) {
        if (!isStateDiscriminantExpr(node.discriminant)) return;
        const defaultCase = (node.cases ?? []).find((c) => c.test === null);
        if (!defaultCase || !containsNeverOrExhaustive(defaultCase)) {
          context.report({ node, messageId: "nonExhaustiveSwitch" });
        }
      },
      "Program:exit"() {
        if (mutatingFns.size < 2) return;
        const entries = [...mutatingFns.entries()];
        context.report({
          node: entries[0][1],
          messageId: "scatteredMutation",
          data: {
            count: String(entries.length),
            names: entries.map(([name]) => name).slice(0, 5).join(", "),
          },
        });
      },
    };
  },
};

export default {
  meta: {
    name: "verification-stack-state-machine",
  },
  rules: {
    "no-implicit-state-machine": noImplicitStateMachineRule,
  },
};
