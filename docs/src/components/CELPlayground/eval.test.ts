import { describe, it, expect } from "vitest";
import { Environment } from "@marcbachmann/cel-js";
import { evaluate, analyzeAST, DEFAULT_EXPRESSION, DEFAULT_YAML } from "./eval";

describe("evaluate", () => {
  it("evaluates the default expression and YAML successfully", () => {
    const result = evaluate(DEFAULT_EXPRESSION, DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
  });

  it("returns BLOCKLIST for a false expression", () => {
    const result = evaluate(
      "target.signing_time < timestamp('2025-01-01T00:00:00Z')",
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("BLOCKLIST");
  });

  it("returns a named constant for enum results", () => {
    const result = evaluate("SILENT_BLOCKLIST", DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.value).toBe("SILENT_BLOCKLIST");
  });

  it("marks expressions using only target fields as cacheable", () => {
    const result = evaluate(
      "target.signing_time >= timestamp('2025-01-01T00:00:00Z')",
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(true);
  });

  it("marks expressions referencing args as non-cacheable", () => {
    const result = evaluate(
      'args.exists(a, a == "--verbose")',
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(false);
  });

  it("marks expressions referencing envs as non-cacheable", () => {
    const result = evaluate(
      'envs.HOME == "/Users/user"',
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(false);
  });

  it("marks expressions referencing euid as non-cacheable", () => {
    const result = evaluate("euid == 501", DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(false);
  });

  it("marks expressions referencing cwd as non-cacheable", () => {
    const result = evaluate(
      'cwd.startsWith("/Users")',
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(false);
  });

  it("does not false-positive on dynamic field names in strings", () => {
    // "args" appears as a string literal, not as the variable
    const result = evaluate(
      'target.name == "args"',
      'target:\n  name: "args"',
    );
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(true);
  });

  it("detects V2 constants", () => {
    const result = evaluate("REQUIRE_TOUCHID", DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.isV2).toBe(true);
  });

  it("detects V2 functions", () => {
    const result = evaluate(
      "require_touchid_with_cooldown_minutes(30)",
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.isV2).toBe(true);
  });

  it("detects V2 variable ancestors", () => {
    const yaml = `ancestors:\n  - signing_id: "platform:com.apple.bash"\n    path: "/bin/bash"`;
    const result = evaluate(
      'ancestors.exists(a, a.signing_id == "platform:com.apple.bash")',
      yaml,
    );
    expect(result.valid).toBe(true);
    expect(result.isV2).toBe(true);
    expect(result.cacheable).toBe(false);
  });

  it("marks V1-only expressions as not V2", () => {
    const result = evaluate("ALLOWLIST", DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.isV2).toBe(false);
  });

  it("returns an error for invalid CEL syntax", () => {
    const result = evaluate("invalid %%% expression", DEFAULT_YAML);
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("returns an error for invalid YAML", () => {
    const result = evaluate("true", "not: valid: yaml: [");
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("returns an error when YAML is not a mapping", () => {
    const result = evaluate("true", '"just a string"');
    expect(result.valid).toBe(false);
    expect(result.error).toBe("YAML input must be a mapping");
  });

  it("handles secure_signing_time", () => {
    const yaml = `target:\n  secure_signing_time: "2025-06-01T00:00:00Z"`;
    const result = evaluate(
      "target.secure_signing_time >= timestamp('2025-01-01T00:00:00Z')",
      yaml,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
  });
});

describe("analyzeAST", () => {
  it("extracts identifiers and calls from a cel-js AST", () => {
    // Parse with the real cel-js parser so this test breaks if the
    // library changes its AST shape in a way analyzeAST doesn't handle.
    const env = new Environment({ unlistedVariablesAreDyn: true });

    // "foo.bar(baz)" is a receiver-call in CEL:
    //   { op: "rcall", args: ["bar", {op:"id",args:"foo"}, [{op:"id",args:"baz"}]] }
    const ast = env.parse("foo.bar(baz)").ast;
    const result = analyzeAST(ast);

    expect(result.identifiers).toContain("foo");
    expect(result.identifiers).toContain("baz");

    // "somefunc(x)" is a plain call:
    //   { op: "call", args: ["somefunc", [{op:"id",args:"x"}]] }
    const ast2 = env.parse("somefunc(x)").ast;
    const result2 = analyzeAST(ast2);

    expect(result2.identifiers).toContain("x");
    expect(result2.calls).toContain("somefunc");
  });
});
