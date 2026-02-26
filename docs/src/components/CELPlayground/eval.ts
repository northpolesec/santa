import { Environment } from "@marcbachmann/cel-js";
import { parse as parseYAML } from "yaml";
import {
  VARIABLES,
  v1Entries,
  v2Entries,
} from "./constants";
import { celWorkshopFunctions } from "./autocompletion";


export const DEFAULT_EXPRESSION = `target.signing_time >= timestamp('2025-05-31T00:00:00Z')`;

export const DEFAULT_YAML = `target:
  signing_id: "EQHXZ8M8AV:com.google.Chrome"
  signing_time: "2025-06-01T00:00:00Z"
args:
  - "--flag"
envs:
  HOME: "/Users/user"
euid: 501
cwd: "/Users/user"
ancestors:
  - signing_id: "platform:com.apple.Terminal"
    team_id: ""
    path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
    cdhash: "abc123"`;

function buildEnvironment(): Environment {
  const env = new Environment({ unlistedVariablesAreDyn: true });

  // Register execution context variables
  env.registerVariable("target", "map");
  env.registerVariable("args", "list");
  env.registerVariable("envs", "map");
  env.registerVariable("euid", "int");
  env.registerVariable("cwd", "string");
  env.registerVariable("ancestors", "list");

  // Register all V2 enum constants (superset of V1)
  for (const [name, value] of Object.entries(v2Entries.nameToValue)) {
    env.registerConstant(name, "int", value);
  }

  // Register V2 custom functions
  // Note: These return fixed values; the minutes parameter is ignored
  // since actual TouchID behavior cannot be simulated in a playground.
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

export function analyzeAST(node: any): {
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
  for (const name of Object.keys(v2Entries.nameToValue)) {
    if (!(name in v1Entries.nameToValue) && identifiers.has(name)) return true;
  }
  if (VARIABLES.some((v) => v.v2Only && identifiers.has(v.name))) return true;
  if (celWorkshopFunctions.some((f) => f.v2Only && calls.has(f.label)))
    return true;
  return false;
}

function isCacheable(identifiers: Set<string>): boolean {
  return !VARIABLES.some((v) => v.dynamic && identifiers.has(v.name));
}

export interface EvalResult {
  valid: boolean;
  value?: string;
  cacheable?: boolean;
  isV2?: boolean;
  error?: string;
}

const celEnv = buildEnvironment();

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
