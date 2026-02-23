import { ReturnValueSchema as V1ReturnValueSchema } from "@buf/northpolesec_protos.bufbuild_es/cel/v1_pb.js";
import { ReturnValueSchema as V2ReturnValueSchema } from "@buf/northpolesec_protos.bufbuild_es/celv2/v2_pb.js";
import { CELVariable } from "./autocompletion";

export const VARIABLES: CELVariable[] = [
  { name: "envs", type: "map", documentation: "Environment variables" },
  { name: "args", type: "list", documentation: "Command line arguments" },
  { name: "euid", type: "int", documentation: "Effective user ID" },
  { name: "cwd", type: "string", documentation: "Current working directory" },
  {
    name: "target.signing_id",
    type: "string",
    documentation:
      "Signing ID of the target binary, prefixed with Team ID or 'platform' (e.g. 'EQHXZ8M8AV:com.google.Chrome' or 'platform:com.apple.curl')",
  },
  {
    name: "target.signing_time",
    type: "timestamp",
    documentation: "Code signing timestamp",
  },
  {
    name: "target.secure_signing_time",
    type: "timestamp",
    documentation: "Secure code signing timestamp",
  },
  { name: "ALLOWLIST", type: "string", documentation: "Allow policy constant" },
  { name: "BLOCKLIST", type: "string", documentation: "Block policy constant" },
  {
    name: "ALLOWLIST_COMPILER",
    type: "string",
    documentation: "Allow compiler policy constant",
  },
  {
    name: "SILENT_BLOCKLIST",
    type: "string",
    documentation: "Silent block policy constant",
  },
  {
    name: "REQUIRE_TOUCHID",
    type: "string",
    documentation: "Require Touch ID policy constant",
  },
  {
    name: "REQUIRE_TOUCHID_ONLY",
    type: "string",
    documentation: "Require Touch ID only policy constant",
  },
];

export const DYNAMIC_FIELDS = ["args", "envs", "euid", "cwd"] as const;

export const V2_ONLY_FUNCTIONS = [
  "require_touchid_with_cooldown_minutes",
  "require_touchid_only_with_cooldown_minutes",
] as const;

export const FUNCTIONS = ["timestamp", ...V2_ONLY_FUNCTIONS] as const;

// Build enum name→value and value→name maps from proto descriptors
function enumEntries(schema: {
  values: readonly { name: string; number: number }[];
}) {
  const nameToValue: Record<string, bigint> = {};
  const valueToName: Record<string, string> = {};
  for (const v of schema.values) {
    if (v.name === "UNSPECIFIED") continue;
    nameToValue[v.name] = BigInt(v.number);
    valueToName[String(BigInt(v.number))] = v.name;
  }
  return { nameToValue, valueToName };
}

export const v1Entries = enumEntries(V1ReturnValueSchema);
export const v2Entries = enumEntries(V2ReturnValueSchema);

export const CONSTANT_NAMES = Object.keys(v2Entries.nameToValue);

// V2-only constant names (not in V1)
export const V2_ONLY_CONSTANTS = new Set(
  CONSTANT_NAMES.filter((name) => !(name in v1Entries.nameToValue)),
);
