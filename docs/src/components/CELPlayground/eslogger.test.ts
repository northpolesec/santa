import { describe, it, expect } from "vitest";
import { parse as parseYAML } from "yaml";
import { convertEsloggerEvent } from "./eslogger";

function toObject(yaml: string): Record<string, any> {
  return parseYAML(yaml);
}

const MINIMAL_EXEC_EVENT = JSON.stringify({
  event: {
    exec: {
      args: ["/usr/bin/ls", "-la"],
      env: ["HOME=/Users/test", "PATH=/usr/bin"],
      target: { audit_token: { euid: 501 } },
      cwd: { path: "/Users/test" },
    },
  },
});

describe("convertEsloggerEvent", () => {
  it("extracts args from an exec event", () => {
    const result = toObject(convertEsloggerEvent(MINIMAL_EXEC_EVENT));
    expect(result.args).toEqual(["/usr/bin/ls", "-la"]);
  });

  it("converts env array to a map", () => {
    const result = toObject(convertEsloggerEvent(MINIMAL_EXEC_EVENT));
    expect(result.envs).toEqual({ HOME: "/Users/test", PATH: "/usr/bin" });
  });

  it("extracts euid from audit token", () => {
    const result = toObject(convertEsloggerEvent(MINIMAL_EXEC_EVENT));
    expect(result.euid).toBe(501);
  });

  it("extracts cwd path", () => {
    const result = toObject(convertEsloggerEvent(MINIMAL_EXEC_EVENT));
    expect(result.cwd).toBe("/Users/test");
  });

  it("always includes an empty target map", () => {
    const result = toObject(convertEsloggerEvent(MINIMAL_EXEC_EVENT));
    expect(result.target).toEqual({});
  });

  it("handles env values containing '='", () => {
    const event = JSON.stringify({
      event: {
        exec: {
          env: ["OPTS=--foo=bar"],
        },
      },
    });
    const result = toObject(convertEsloggerEvent(event));
    expect(result.envs).toEqual({ OPTS: "--foo=bar" });
  });

  it("handles missing optional fields", () => {
    const event = JSON.stringify({ event: { exec: {} } });
    const result = toObject(convertEsloggerEvent(event));
    expect(result.target).toEqual({});
    expect(result.args).toBeUndefined();
    expect(result.envs).toBeUndefined();
    expect(result.euid).toBeUndefined();
    expect(result.cwd).toBeUndefined();
  });

  it("picks the first exec event from newline-delimited JSON", () => {
    const line1 = JSON.stringify({
      event: { exec: { args: ["/bin/first"], cwd: { path: "/first" } } },
    });
    const line2 = JSON.stringify({
      event: { exec: { args: ["/bin/second"], cwd: { path: "/second" } } },
    });
    const result = toObject(convertEsloggerEvent(line1 + "\n" + line2));
    expect(result.args).toEqual(["/bin/first"]);
    expect(result.cwd).toBe("/first");
  });

  it("skips non-exec events in newline-delimited input", () => {
    const nonExec = JSON.stringify({ event: { open: {} } });
    const exec = JSON.stringify({
      event: { exec: { args: ["/bin/ls"] } },
    });
    const result = toObject(convertEsloggerEvent(nonExec + "\n" + exec));
    expect(result.args).toEqual(["/bin/ls"]);
  });

  it("throws for input with no exec event", () => {
    expect(() => convertEsloggerEvent("{}")).toThrow(
      "No exec event found in eslogger output",
    );
  });

  it("throws for invalid JSON", () => {
    expect(() => convertEsloggerEvent("not json at all")).toThrow();
  });

  it("returns valid YAML that can be round-tripped", () => {
    const yaml = convertEsloggerEvent(MINIMAL_EXEC_EVENT);
    const parsed = parseYAML(yaml);
    expect(typeof parsed).toBe("object");
    expect(parsed).not.toBeNull();
  });
});
