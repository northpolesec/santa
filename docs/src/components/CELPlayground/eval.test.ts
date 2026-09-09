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

  it.each([
    "SILENT_BLOCKLIST",
    "SILENT_GUI_BLOCKLIST",
    "SILENT_TTY_BLOCKLIST",
  ])("returns a named constant for the %s enum result", (name) => {
    const result = evaluate(name, DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.value).toBe(name);
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

  it("marks expressions referencing path as non-cacheable", () => {
    const result = evaluate(
      'path.startsWith("/Applications")',
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(false);
  });

  it("evaluates target.is_platform_binary", () => {
    const result = evaluate(
      "target.is_platform_binary == false",
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    expect(result.cacheable).toBe(true);
  });

  it("evaluates target.team_id", () => {
    const result = evaluate(
      'target.team_id == "EQHXZ8M8AV"',
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    expect(result.cacheable).toBe(true);
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

  it("evaluates today() - days(n) against secure_signing_time", () => {
    // Signed ~30 days ago: within the last 90 days -> ALLOWLIST.
    const signed = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const yaml = `target:\n  secure_signing_time: "${signed}"`;
    const result = evaluate(
      "target.secure_signing_time > today() - days(90)",
      yaml,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
  });

  it("days(n) matches the equivalent native duration()", () => {
    const signed = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const yaml = `target:\n  secure_signing_time: "${signed}"`;
    const withDays = evaluate(
      "target.secure_signing_time > today() - days(90)",
      yaml,
    );
    const withDuration = evaluate(
      "target.secure_signing_time > today() - duration('2160h')",
      yaml,
    );
    // Guard against both evaluations failing (undefined === undefined).
    expect(withDays.valid).toBe(true);
    expect(withDuration.valid).toBe(true);
    expect(withDays.value).toBe("ALLOWLIST");
    expect(withDays.value).toBe(withDuration.value);
  });

  it("marks expressions using today() as non-cacheable and V2", () => {
    const result = evaluate(
      "target.signing_time > today() - days(90)",
      DEFAULT_YAML,
    );
    expect(result.valid).toBe(true);
    expect(result.cacheable).toBe(false);
    expect(result.isV2).toBe(true);
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

// Time based rules. Every context pins the clock with the playground-only `now`
// key; its UTC offset stands in for the host's time zone. 2026-09-14 is a
// Monday and 2026-09-12 a Saturday.
const HOST_EDT_MONDAY_1030 = `now: "2026-09-14T10:30:00-04:00"`;
const HOST_EDT_SATURDAY_1400 = `now: "2026-09-12T14:00:00-04:00"`;

describe("time based rules", () => {
  it("strips the now override from the context and pins the clock", () => {
    const result = evaluate(
      `now() == timestamp("2026-09-14T14:30:00Z")`,
      HOST_EDT_MONDAY_1030,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    expect(result.cacheable).toBe(false);
    expect(result.isV2).toBe(true);
  });

  it("uses the real clock when now is absent", () => {
    const result = evaluate(`now() > timestamp("2020-01-01T00:00:00Z")`, DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
  });

  it("rejects an unparseable now", () => {
    const result = evaluate("ALLOWLIST", `now: "yesterday"`);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/now/);
  });

  it("today() is the start of the host's local day", () => {
    // Midnight at UTC-4 is 04:00Z.
    const result = evaluate(
      `today() == timestamp("2026-09-14T04:00:00Z")`,
      HOST_EDT_MONDAY_1030,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    expect(result.cacheable).toBe(false);
  });

  it("today(tz) is the start of the day in the named zone", () => {
    for (const [expr, expected] of [
      [`today("UTC") == timestamp("2026-09-14T00:00:00Z")`, "ALLOWLIST"],
      [`today("America/New_York") == timestamp("2026-09-14T04:00:00Z")`, "ALLOWLIST"],
      [`today("+05:30") == timestamp("2026-09-13T18:30:00Z")`, "ALLOWLIST"],
      [`today("local") == today()`, "ALLOWLIST"],
    ] as const) {
      const result = evaluate(expr, HOST_EDT_MONDAY_1030);
      expect(result.valid, expr).toBe(true);
      expect(result.value, expr).toBe(expected);
      expect(result.cacheable, expr).toBe(false);
      expect(result.isV2, expr).toBe(true);
    }
  });

  it("today(tz) rejects an unknown zone", () => {
    const result = evaluate(`today("Mars/Olympus") > timestamp(0)`, HOST_EDT_MONDAY_1030);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/unknown time zone/);
  });

  it("weekdays() is Monday through Friday and does not affect caching", () => {
    const result = evaluate("weekdays() == [1, 2, 3, 4, 5]", DEFAULT_YAML);
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    expect(result.cacheable).toBe(true);
    expect(result.isV2).toBe(true);
  });

  it("weekly window: in range on a weekday morning", () => {
    const result = evaluate(
      `policy_for_range(weekdays(), "09:00", "17:00", ALLOWLIST, BLOCKLIST)`,
      HOST_EDT_MONDAY_1030,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    expect(result.cacheable).toBe(false);
    expect(result.isV2).toBe(true);
    expect(result.pendingKill).toBeUndefined();
  });

  it("weekly window: out of range on a weekend returns the out-of-range policy", () => {
    const result = evaluate(
      `policy_for_range(weekdays(), "09:00", "17:00", ALLOWLIST, AUDIT)`,
      HOST_EDT_SATURDAY_1400,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("AUDIT");
  });

  it("weekly window: Touch ID out of hours keeps its cooldown policy", () => {
    const result = evaluate(
      `policy_for_range(weekdays(), "08:00", "18:00", ALLOWLIST, require_touchid_with_cooldown_minutes(60))`,
      `now: "2026-09-14T21:15:00-04:00"`,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("REQUIRE_TOUCHID");
  });

  it("weekly window in a named zone ignores the host's zone", () => {
    // 23:30 at UTC-4 is 03:30Z, inside 01:00 to 05:00 UTC.
    const result = evaluate(
      `policy_for_range([0, 1, 2, 3, 4, 5, 6], "01:00", "05:00", "UTC", ALLOWLIST, BLOCKLIST)`,
      `now: "2026-09-14T23:30:00-04:00"`,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
  });

  it("weekly window: a day list of [] never opens", () => {
    const result = evaluate(
      `policy_for_range([], "00:00", "00:00", ALLOWLIST, BLOCKLIST)`,
      HOST_EDT_MONDAY_1030,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("BLOCKLIST");
  });

  it("fixed span: in and out of range", () => {
    const expr = `policy_for_range(timestamp("2026-09-14T00:00:00Z"), timestamp("2026-09-21T00:00:00Z"), ALLOWLIST, BLOCKLIST)`;
    expect(evaluate(expr, `now: "2026-09-17T12:00:00Z"`).value).toBe("ALLOWLIST");
    expect(evaluate(expr, `now: "2026-09-21T00:00:00Z"`).value).toBe("BLOCKLIST");
  });

  it("duration form records a quit a duration after the execution", () => {
    const result = evaluate(
      `policy_for_range(duration("30m"), kill_on_expiry(ALLOWLIST))`,
      HOST_EDT_MONDAY_1030,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    expect(result.cacheable).toBe(false);
    // 10:30 at UTC-4 is 14:30Z; a 30 minute window warns 5 minutes ahead.
    expect(result.pendingKill?.deadline.toISOString()).toBe("2026-09-14T15:00:00.000Z");
    expect(result.pendingKill?.notifyAt.toISOString()).toBe("2026-09-14T14:55:00.000Z");
  });

  it("kill_on_expiry on a weekly window records the end of the occurrence", () => {
    const result = evaluate(
      `policy_for_range(weekdays(), "09:00", "17:00", kill_on_expiry(ALLOWLIST), BLOCKLIST)`,
      `now: "2026-09-14T15:45:00-04:00"`,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("ALLOWLIST");
    // 17:00 at UTC-4 is 21:00Z; an 8 hour window warns 48 minutes ahead.
    expect(result.pendingKill?.deadline.toISOString()).toBe("2026-09-14T21:00:00.000Z");
    expect(result.pendingKill?.notifyAt.toISOString()).toBe("2026-09-14T20:12:00.000Z");
  });

  it("kill_on_expiry records nothing when the window is closed", () => {
    const result = evaluate(
      `policy_for_range(weekdays(), "09:00", "17:00", kill_on_expiry(ALLOWLIST), BLOCKLIST)`,
      HOST_EDT_SATURDAY_1400,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("BLOCKLIST");
    expect(result.pendingKill).toBeUndefined();
  });

  it("kill_on_expiry passes a Touch ID cooldown policy through", () => {
    const result = evaluate(
      `policy_for_range(duration("30m"), kill_on_expiry(require_touchid_with_cooldown_minutes(30)))`,
      HOST_EDT_MONDAY_1030,
    );
    expect(result.valid).toBe(true);
    expect(result.value).toBe("REQUIRE_TOUCHID");
    expect(result.pendingKill).toBeDefined();
  });

  it("a ternary scopes the window to some executions", () => {
    const expr = `"--beta" in args ? policy_for_range(duration("30m"), kill_on_expiry(ALLOWLIST)) : ALLOWLIST`;
    const timed = evaluate(expr, `${HOST_EDT_MONDAY_1030}\nargs:\n  - "--beta"`);
    expect(timed.valid).toBe(true);
    expect(timed.value).toBe("ALLOWLIST");
    expect(timed.pendingKill).toBeDefined();

    const plain = evaluate(expr, `${HOST_EDT_MONDAY_1030}\nargs:\n  - "--flag"`);
    expect(plain.valid).toBe(true);
    expect(plain.value).toBe("ALLOWLIST");
    expect(plain.pendingKill).toBeUndefined();
  });

  it.each([
    [`policy_for_range(duration("30m"), ALLOWLIST)`, /requires kill_on_expiry/],
    [`policy_for_range(duration("0s"), kill_on_expiry(ALLOWLIST))`, /must be positive/],
    [`kill_on_expiry(ALLOWLIST)`, /in-range policy of policy_for_range/],
    [`policy_for_range(duration("30m"), kill_on_expiry(BLOCKLIST))`, /does not allow a process to start/],
    [`policy_for_range(weekdays(), "09:00", "17:00", ALLOWLIST, kill_on_expiry(ALLOWLIST))`, /in-range policy of policy_for_range/],
    [`policy_for_range(duration("30m"), kill_on_expiry("-x" in args ? AUDIT : ALLOWLIST))`, /statically known/],
    [`policy_for_range(duration("30m"), kill_on_expiry(ALLOWLIST)) == ALLOWLIST ? ALLOWLIST : BLOCKLIST`, /must produce the rule's result/],
    [`policy_for_range(weekdays(), "09:00", "17:00", ALLOWLIST, BLOCKLIST) && euid == 0`, /bool/],
    [`policy_for_range([0, 1, 2, 3, 4, 5, 6], "00:00", "00:00", policy_for_range(duration("30m"), kill_on_expiry(ALLOWLIST)), BLOCKLIST)`, /nested/],
    [`policy_for_range([1], "9:00", "17:00", ALLOWLIST, BLOCKLIST)`, /HH:MM/],
    [`policy_for_range([7], "09:00", "17:00", ALLOWLIST, BLOCKLIST)`, /0 \(Sunday\) through 6 \(Saturday\)/],
    [`policy_for_range([1], "09:00", "17:00", "Mars/Olympus", ALLOWLIST, BLOCKLIST)`, /unknown time zone/],
  ])("refuses %s", (expr, message) => {
    const result = evaluate(expr, `${HOST_EDT_MONDAY_1030}\neuid: 0\nargs:\n  - "-x"`);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(message);
  });
});
