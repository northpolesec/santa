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
  const event = JSON.parse(input);
  if (event?.event?.exec) return event;
  throw new Error("No exec event found in eslogger output");
}

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

  return stringifyYAML(context);
}
