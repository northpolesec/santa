import { stringify as stringifyYAML } from "yaml";

function parseExecEvent(input: string): Record<string, any> {
  // Handle newline-delimited JSON (multiple eslogger events)
  const lines = input.split("\n").filter((l) => l.trim());
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      if (event?.event?.exec) return event;
    } catch {
      // skip non-JSON lines
    }
  }

  // Try parsing the whole input as a single JSON object
  try {
    const event = JSON.parse(input);
    if (event?.event?.exec) return event;
  } catch {
    // fall through to consistent error
  }
  throw new Error("No exec event found in eslogger output");
}

// Map eslogger PROX_FDTYPE_* values to CEL proto FD_TYPE_* values.
// The numeric values differ: e.g. PROX_FDTYPE_VNODE=1 but FD_TYPE_VNODE=2.
const FDTYPE_ES_TO_CEL: Record<number, number> = {
  0: 1,   // PROX_FDTYPE_ATALK   → FD_TYPE_ATALK
  1: 2,   // PROX_FDTYPE_VNODE   → FD_TYPE_VNODE
  2: 3,   // PROX_FDTYPE_SOCKET  → FD_TYPE_SOCKET
  3: 4,   // PROX_FDTYPE_PSHM    → FD_TYPE_PSHM
  4: 5,   // PROX_FDTYPE_PSEM    → FD_TYPE_PSEM
  5: 6,   // PROX_FDTYPE_KQUEUE  → FD_TYPE_KQUEUE
  6: 7,   // PROX_FDTYPE_PIPE    → FD_TYPE_PIPE
  7: 8,   // PROX_FDTYPE_FSEVENTS → FD_TYPE_FSEVENTS
  9: 9,   // PROX_FDTYPE_NETPOLICY → FD_TYPE_NETPOLICY
  10: 10, // PROX_FDTYPE_CHANNEL → FD_TYPE_CHANNEL
  11: 11, // PROX_FDTYPE_NEXUS   → FD_TYPE_NEXUS
};

export function convertEsloggerEvent(input: string): string {
  const event = parseExecEvent(input);
  const exec = event.event.exec;

  const context: Record<string, any> = {};

  // target: extract signing timestamps if available (not typically in eslogger)
  context.target = {};

  // args
  if (Array.isArray(exec.args)) {
    context.args = exec.args;
  }

  // env: array of "KEY=value" strings → map
  if (Array.isArray(exec.env)) {
    const envs: Record<string, string> = {};
    for (const entry of exec.env) {
      const idx = entry.indexOf("=");
      if (idx !== -1) {
        envs[entry.slice(0, idx)] = entry.slice(idx + 1);
      }
    }
    context.envs = envs;
  }

  // euid from target audit token
  if (exec.target?.audit_token?.euid != null) {
    context.euid = exec.target.audit_token.euid;
  }

  // cwd
  if (exec.cwd?.path) {
    context.cwd = exec.cwd.path;
  }

  // path: executable file path
  if (exec.target?.executable?.path) {
    context.path = exec.target.executable.path;
  }

  // signing_id: format as "teamID:signingID" or "platform:signingID"
  const target = exec.target;
  if (target?.signing_id) {
    if (target.is_platform_binary && !target.team_id) {
      context.target.signing_id = "platform:" + target.signing_id;
    } else if (target.team_id) {
      context.target.signing_id = target.team_id + ":" + target.signing_id;
    }
  }

  // is_platform_binary and team_id
  if (target?.is_platform_binary != null) {
    context.target.is_platform_binary = target.is_platform_binary;
  }
  if (target?.team_id) {
    context.target.team_id = target.team_id;
  }

  // fds: array of {fd, fdtype} → {fd, type} with PROX_FDTYPE→FD_TYPE mapping
  if (Array.isArray(exec.fds)) {
    context.fds = exec.fds.map((entry: any) => ({
      fd: entry.fd,
      type: FDTYPE_ES_TO_CEL[entry.fdtype] ?? 0, // unknown types → FD_TYPE_UNKNOWN
    }));
  }

  // Make up signing times and ancestors (eslogger events don't include these)
  context.target.signing_time = "2025-06-01T00:00:00Z";
  context.target.secure_signing_time = "2025-06-01T00:00:00Z";
  context.ancestors = [
    {
      signing_id: "platform:com.apple.Terminal",
      team_id: "",
      path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
      cdhash: "",
    },
  ];

  const yaml = stringifyYAML(context);
  return "# Note: signing times and ancestors are fake — eslogger events don't include them\n" + yaml;
}
