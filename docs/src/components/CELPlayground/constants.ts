import { ReturnValueSchema as V1ReturnValueSchema } from "@buf/northpolesec_protos.bufbuild_es/cel/v1_pb.js";
import { ReturnValueSchema as V2ReturnValueSchema } from "@buf/northpolesec_protos.bufbuild_es/celv2/v2_pb.js";
import { CELVariable } from "./autocompletion";

export const VARIABLES: CELVariable[] = [
  { name: "envs", type: "map", dynamic: true, documentation: "Environment variables" },
  { name: "args", type: "list", dynamic: true, documentation: "Command line arguments" },
  { name: "euid", type: "int", dynamic: true, documentation: "Effective user ID" },
  { name: "cwd", type: "string", dynamic: true, documentation: "Current working directory" },
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
  {
    name: "ancestors",
    type: "list",
    dynamic: true,
    v2Only: true,
    documentation:
      "List of ancestor processes in the execution chain. Each ancestor has signing_id, team_id, path, and cdhash fields.",
    itemFields: [
      {
        name: "signing_id",
        type: "string",
        documentation:
          "Signing ID of the ancestor binary, prefixed with Team ID or 'platform'",
      },
      { name: "team_id", type: "string", documentation: "Team ID from code signature" },
      { name: "path", type: "string", documentation: "Path to the ancestor binary" },
      { name: "cdhash", type: "string", documentation: "Code directory hash" },
    ],
  },
];

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

