import { Environment, ParseError, EvaluationError } from "@marcbachmann/cel-js";
import { parse as parseYAML } from "yaml";
import { setConstantNames } from "./autocompletion";

import {
  ReturnValue as V1ReturnValue,
  ReturnValueSchema as V1ReturnValueSchema,
} from "@buf/northpolesec_protos.bufbuild_es/cel/v1_pb.js";
import {
  ReturnValue as V2ReturnValue,
  ReturnValueSchema as V2ReturnValueSchema,
} from "@buf/northpolesec_protos.bufbuild_es/celv2/v2_pb.js";

// Build enum name→value and value→name maps from proto descriptors
function enumEntries(schema: { values: readonly { name: string; number: number }[] }) {
  const nameToValue: Record<string, bigint> = {};
  const valueToName: Record<string, string> = {};
  for (const v of schema.values) {
    if (v.name === "UNSPECIFIED") continue;
    nameToValue[v.name] = BigInt(v.number);
    valueToName[String(BigInt(v.number))] = v.name;
  }
  return { nameToValue, valueToName };
}

const v1Entries = enumEntries(V1ReturnValueSchema);
const v2Entries = enumEntries(V2ReturnValueSchema);

// V2-only constant names (not in V1)
const V2_ONLY_CONSTANTS = new Set(
  Object.keys(v2Entries.nameToValue).filter(
    (name) => !(name in v1Entries.nameToValue),
  ),
);

import { V2_ONLY_FUNCTIONS, DYNAMIC_FIELDS } from "./constants";

export const DEFAULT_EXPRESSION = `target.signing_time >= timestamp('2025-05-31T00:00:00Z')`;

export const DEFAULT_YAML = `target:
  signing_time: "2025-06-01T00:00:00Z"
args:
  - "--flag"
envs:
  HOME: "/Users/user"
euid: 501
cwd: "/Users/user"`;

function buildEnvironment(): Environment {
  const env = new Environment({ unlistedVariablesAreDyn: true });

  // Register execution context variables
  env.registerVariable("target", "map");
  env.registerVariable("args", "list");
  env.registerVariable("envs", "map");
  env.registerVariable("euid", "int");
  env.registerVariable("cwd", "string");

  // Register all V2 enum constants (superset of V1)
  for (const [name, value] of Object.entries(v2Entries.nameToValue)) {
    env.registerConstant(name, "int", value);
  }

  // Register V2 custom functions
  env.registerFunction(
    "require_touchid_with_cooldown_minutes(int): int",
    (_minutes: bigint) => v2Entries.nameToValue["REQUIRE_TOUCHID"],
  );
  env.registerFunction(
    "require_touchid_only_with_cooldown_minutes(int): int",
    (_minutes: bigint) => v2Entries.nameToValue["REQUIRE_TOUCHID_ONLY"],
  );

  return env;
}

function prepareContext(parsed: Record<string, any>): Record<string, any> {
  const ctx = { ...parsed };

  if (ctx.target && typeof ctx.target === "object") {
    ctx.target = { ...ctx.target };
    if (typeof ctx.target.signing_time === "string") {
      ctx.target.signing_time = new Date(ctx.target.signing_time);
    }
    if (typeof ctx.target.secure_signing_time === "string") {
      ctx.target.secure_signing_time = new Date(ctx.target.secure_signing_time);
    }
  }

  if (typeof ctx.euid === "number") {
    ctx.euid = BigInt(ctx.euid);
  }

  return ctx;
}

function mapResultToName(value: any): string {
  if (value === true) return "ALLOWLIST";
  if (value === false) return "BLOCKLIST";
  if (typeof value === "bigint") {
    const name = v2Entries.valueToName[String(value)];
    if (name) return name;
    return `Unknown (${value})`;
  }
  return String(value);
}

function analyzeAST(node: any): {
  identifiers: Set<string>;
  calls: Set<string>;
} {
  const identifiers = new Set<string>();
  const calls = new Set<string>();
  (function walk(n: any) {
    if (!n || typeof n !== "object") return;
    if (Array.isArray(n)) {
      for (const item of n) walk(item);
      return;
    }
    if ("op" in n) {
      if (n.op === "id") {
        identifiers.add(n.args);
        return;
      }
      if (n.op === "call") calls.add(n.args[0]);
      walk(n.args);
    }
  })(node);
  return { identifiers, calls };
}

function usesV2Features(
  identifiers: Set<string>,
  calls: Set<string>,
): boolean {
  for (const name of V2_ONLY_CONSTANTS) {
    if (identifiers.has(name)) return true;
  }
  for (const fn of V2_ONLY_FUNCTIONS) {
    if (calls.has(fn)) return true;
  }
  return false;
}

function isCacheable(identifiers: Set<string>): boolean {
  return !DYNAMIC_FIELDS.some((field) => identifiers.has(field));
}

export interface EvalResult {
  valid: boolean;
  value?: string;
  cacheable?: boolean;
  isV2?: boolean;
  error?: string;
}

const celEnv = buildEnvironment();

setConstantNames(Object.keys(v2Entries.nameToValue));

export function evaluate(expression: string, yamlInput: string): EvalResult {
  try {
    const parsed = parseYAML(yamlInput);
    if (typeof parsed !== "object" || parsed === null) {
      return { valid: false, error: "YAML input must be a mapping" };
    }

    const ctx = prepareContext(parsed);
    const evalFn = celEnv.parse(expression);
    const { identifiers, calls } = analyzeAST(evalFn.ast);
    const value = evalFn(ctx);
    const displayValue = mapResultToName(value);
    const cacheable = isCacheable(identifiers);
    const isV2 = usesV2Features(identifiers, calls);

    return { valid: true, value: displayValue, cacheable, isV2 };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { valid: false, error: message };
  }
}
