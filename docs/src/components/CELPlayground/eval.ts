import { Environment } from "@marcbachmann/cel-js";
import { Duration } from "@marcbachmann/cel-js/evaluator";
import { parse as parseYAML } from "yaml";
import {
  VARIABLES,
  v1Entries,
  v2Entries,
} from "./constants";
import { celWorkshopFunctions } from "./autocompletion";
import {
  type Zone,
  type WindowEval,
  browserZone,
  zoneFromISOOffset,
  resolveZone,
  toCivil,
  fromCivil,
  evalDaysHHMMWindow,
  evalTimestampWindow,
  evalDurationWindow,
  notificationLeadMs,
} from "./timewindow";


export const DEFAULT_EXPRESSION = `target.signing_time >= timestamp('2025-05-31T00:00:00Z')`;

export const DEFAULT_YAML = `target:
  signing_id: "EQHXZ8M8AV:com.google.Chrome"
  signing_time: "2025-06-01T00:00:00Z"
  is_platform_binary: false
  team_id: "EQHXZ8M8AV"
args:
  - "--flag"
envs:
  HOME: "/Users/user"
euid: 501
cwd: "/Users/user"
path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
ancestors:
  - signing_id: "platform:com.apple.Terminal"
    team_id: ""
    path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
    cdhash: "abc123"
fds:
  - fd: 0
    type: 2
  - fd: 1
    type: 7
  - fd: 2
    type: 7`;

// The clock one evaluation reads: the instant, and the zone that "local" means.
// By default it is the real clock in the browser's zone. The playground-only
// `now` key in the context pins both: its value is the instant and its UTC
// offset stands in for the host's time zone.
interface Clock {
  now: Date;
  local: Zone;
}

let clockOverride: Clock | null = null;

function currentClock(): Clock {
  return clockOverride ?? { now: new Date(), local: browserZone() };
}

// The quit an in-window kill_on_expiry() asked for, mirroring santad's
// PendingKill: quit at `deadline`, having warned at `notifyAt`.
export interface PendingKill {
  deadline: Date;
  notifyAt: Date;
}

let pendingKill: PendingKill | undefined;

// One expression can call policy_for_range() more than once; the earliest
// deadline governs, and the warning never precedes the evaluation itself.
function recordPendingKill(windowEnd: Date, windowLengthMs: number) {
  const now = currentClock().now;
  const lead = notificationLeadMs(windowLengthMs);
  const notifyAt = new Date(Math.max(windowEnd.getTime() - lead, now.getTime()));
  if (!pendingKill || windowEnd.getTime() < pendingKill.deadline.getTime()) {
    pendingKill = { deadline: windowEnd, notifyAt };
  }
}

// kill_on_expiry() wraps a policy in a grant. cel-js only passes plain values
// between functions, so a grant is a plain object, and the WeakSet is what
// distinguishes one kill_on_expiry() produced from a map literal that happens
// to look the same.
interface Grant {
  policy: bigint;
}
const grants = new WeakSet<object>();

// Policies that let a process start, and so leave something to quit at expiry.
const GRANTABLE_POLICIES = [
  "ALLOWLIST",
  "AUDIT",
  "SEATBELT",
  "REQUIRE_TOUCHID",
  "REQUIRE_TOUCHID_ONLY",
];
const GRANTABLE_VALUES = new Set(
  GRANTABLE_POLICIES.map((name) => v2Entries.nameToValue[name]),
);
const TOUCHID_HELPERS = [
  "require_touchid_with_cooldown_minutes",
  "require_touchid_only_with_cooldown_minutes",
];

function startOfDay(now: Date, zone: Zone): Date {
  const civil = toCivil(now, zone);
  return fromCivil(
    { year: civil.year, month: civil.month, day: civil.day, hour: 0, minute: 0, second: 0 },
    zone,
  );
}

function durationMs(d: Duration): number {
  return Number(d.seconds) * 1000 + Number(d.nanos ?? 0) / 1e6;
}

interface DecodedPolicy {
  value: bigint;
  killOnExpiry: boolean;
}

function decodePolicy(policy: bigint | object): DecodedPolicy {
  if (typeof policy === "bigint") {
    return { value: policy, killOnExpiry: false };
  }
  if (grants.has(policy)) {
    return { value: (policy as Grant).policy, killOnExpiry: true };
  }
  throw new Error("policy_for_range() expects a policy or kill_on_expiry() policy");
}

// Returns the in-range policy while the window is open, recording the quit a
// grant asks for, and the out-of-range policy otherwise.
function decide(
  window: WindowEval,
  inRange: bigint | object,
  outOfRange: bigint,
): bigint {
  const policy = decodePolicy(inRange);
  if (window.inRange) {
    if (policy.killOnExpiry) {
      recordPendingKill(window.windowEnd!, window.windowLengthMs!);
    }
    return policy.value;
  }
  return outOfRange;
}

function buildEnvironment(): Environment {
  const env = new Environment({ unlistedVariablesAreDyn: true });

  // Register execution context variables
  env.registerVariable("target", "map");
  env.registerVariable("args", "list");
  env.registerVariable("envs", "map");
  env.registerVariable("euid", "int");
  env.registerVariable("cwd", "string");
  env.registerVariable("path", "string");
  env.registerVariable("ancestors", "list");
  env.registerVariable("fds", "list");

  // Register all V2 enum constants (superset of V1)
  for (const [name, value] of Object.entries(v2Entries.nameToValue)) {
    env.registerConstant(name, "int", value);
  }

  // Register FDType enum constants
  const fdTypeValues: Record<string, bigint> = {
    FD_TYPE_UNKNOWN: 0n,
    FD_TYPE_ATALK: 1n,
    FD_TYPE_VNODE: 2n,
    FD_TYPE_SOCKET: 3n,
    FD_TYPE_PSHM: 4n,
    FD_TYPE_PSEM: 5n,
    FD_TYPE_KQUEUE: 6n,
    FD_TYPE_PIPE: 7n,
    FD_TYPE_FSEVENTS: 8n,
    FD_TYPE_NETPOLICY: 9n,
    FD_TYPE_CHANNEL: 10n,
    FD_TYPE_NEXUS: 11n,
  };
  for (const [name, value] of Object.entries(fdTypeValues)) {
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

  // Relative-time helpers (V2). today() is the start of the current day in the
  // host's zone, today(tz) the same in a named zone, and now() the current
  // instant; any expression using them is non-cacheable. days(n) is n*24h,
  // sugar for the day windows that native duration() can't express (it only
  // parses up to hours). weekdays() is the constant [1, 2, 3, 4, 5].
  env.registerFunction("today(): google.protobuf.Timestamp", () => {
    const clock = currentClock();
    return startOfDay(clock.now, clock.local);
  });
  env.registerFunction("today(string): google.protobuf.Timestamp", (tz: string) => {
    const clock = currentClock();
    return startOfDay(clock.now, resolveZone(tz, clock.local));
  });
  env.registerFunction(
    "days(int): google.protobuf.Duration",
    (n: bigint) => new Duration(n * 86400n),
  );
  env.registerFunction("now(): google.protobuf.Timestamp", () => currentClock().now);
  env.registerFunction("weekdays(): list", () => [1n, 2n, 3n, 4n, 5n]);

  // kill_on_expiry(policy) wraps a grantable policy for the in-range slot of
  // policy_for_range(). The placement rules are checked on the AST before
  // evaluation (see validateTimeRules); this is the runtime backstop.
  env.registerFunction("kill_on_expiry(int): map", (policy: bigint) => {
    if (!GRANTABLE_VALUES.has(policy)) {
      const name = v2Entries.valueToName[String(policy)] ?? String(policy);
      throw new Error(
        `${name} cannot be used with kill_on_expiry() because it does not allow a process to start`,
      );
    }
    const grant: Grant = { policy };
    grants.add(grant);
    return grant;
  });

  // policy_for_range(): one overload per window shape, each in a plain and a
  // grant form so the in-range slot can hold either a policy or
  // kill_on_expiry(policy). The out-of-range slot is always a plain policy.
  const weekly = (
    days: bigint[],
    start: string,
    end: string,
    zone: Zone,
    inRange: bigint | object,
    outOfRange: bigint,
  ) => {
    const clock = currentClock();
    return decide(evalDaysHHMMWindow(days, start, end, clock.now, zone), inRange, outOfRange);
  };
  for (const inRangeType of ["int", "map"]) {
    env.registerFunction(
      `policy_for_range(list, string, string, ${inRangeType}, int): int`,
      (days: bigint[], start: string, end: string, inRange: bigint | object, outOfRange: bigint) =>
        weekly(days, start, end, currentClock().local, inRange, outOfRange),
    );
    env.registerFunction(
      `policy_for_range(list, string, string, string, ${inRangeType}, int): int`,
      (
        days: bigint[],
        start: string,
        end: string,
        tz: string,
        inRange: bigint | object,
        outOfRange: bigint,
      ) => weekly(days, start, end, resolveZone(tz, currentClock().local), inRange, outOfRange),
    );
    env.registerFunction(
      `policy_for_range(google.protobuf.Timestamp, google.protobuf.Timestamp, ${inRangeType}, int): int`,
      (start: Date, end: Date, inRange: bigint | object, outOfRange: bigint) =>
        decide(evalTimestampWindow(start, end, currentClock().now), inRange, outOfRange),
    );
  }
  env.registerFunction(
    "policy_for_range(google.protobuf.Duration, map): int",
    (d: Duration, inRange: object) => {
      const ms = durationMs(d);
      if (!(ms > 0)) {
        throw new Error("policy_for_range() duration must be positive");
      }
      // [now, now + d) always contains now, so this form only places a deadline.
      return decide(evalDurationWindow(ms, currentClock().now), inRange, 0n);
    },
  );
  env.registerFunction(
    "policy_for_range(google.protobuf.Duration, int): int",
    () => {
      throw new Error(
        "policy_for_range() with a duration requires kill_on_expiry(): the form exists to expire access",
      );
    },
  );

  return env;
}

// Reads the playground-only `now` key out of the context, if present, and
// returns the clock it pins.
function clockFromContext(parsed: Record<string, any>): Clock | null {
  if (!("now" in parsed)) return null;
  const raw = parsed.now;
  const now = raw instanceof Date ? raw : new Date(String(raw));
  if (Number.isNaN(now.getTime())) {
    throw new Error(
      `now must be an ISO 8601 timestamp such as "2026-09-14T10:30:00-04:00", got ${JSON.stringify(raw)}`,
    );
  }
  const local = typeof raw === "string" ? zoneFromISOOffset(raw) : null;
  return { now, local: local ?? browserZone() };
}

function prepareContext(parsed: Record<string, any>): Record<string, any> {
  const ctx = { ...parsed };
  delete ctx.now;

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

  if (Array.isArray(ctx.fds)) {
    ctx.fds = ctx.fds.map((entry: any) => ({
      ...entry,
      fd: typeof entry.fd === "number" ? BigInt(entry.fd) : entry.fd,
      type: typeof entry.type === "number" ? BigInt(entry.type) : entry.type,
    }));
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

// One step up from a node: the node above it and which argument slot it fills.
interface Ancestor {
  node: any;
  index: number;
}

function isCall(node: any, name: string): boolean {
  return node && typeof node === "object" && node.op === "call" && node.args[0] === name;
}

// The in-range argument index of a policy_for_range() call, by argument count.
function inRangeIndex(call: any): number | undefined {
  switch (call.args[1].length) {
    case 2:
      return 1;
    case 4:
      return 2;
    case 5:
      return 3;
    case 6:
      return 4;
    default:
      return undefined;
  }
}

// The placement rules santad's compiler enforces for time based rules, checked
// on the parsed expression before it runs:
//   - kill_on_expiry() wraps a policy written out in the call, and only one
//     that lets a process start;
//   - it sits in the in-range slot of a policy_for_range() call;
//   - that call reaches the root through ternary branches only, so the quit it
//     records is attached to the rule's own decision;
//   - policy_for_range() is never an argument of another policy_for_range(),
//     because CEL evaluates every argument and the inner window would record a
//     quit for executions it never decided.
export function validateTimeRules(ast: any): void {
  (function walk(node: any, ancestors: Ancestor[]) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach((item) => walk(item, ancestors));
      return;
    }
    if (!("op" in node)) return;

    if (isCall(node, "policy_for_range")) {
      if (ancestors.some((a) => isCall(a.node, "policy_for_range"))) {
        throw new Error(
          "policy_for_range() cannot be nested inside another policy_for_range(); use a ternary",
        );
      }
    }

    if (isCall(node, "kill_on_expiry")) {
      const wrapped = node.args[1][0];
      if (wrapped && wrapped.op === "id") {
        if (!GRANTABLE_POLICIES.includes(wrapped.args)) {
          throw new Error(
            `${wrapped.args} cannot be used with kill_on_expiry() because it does not allow a process to start`,
          );
        }
      } else if (!(wrapped && TOUCHID_HELPERS.some((helper) => isCall(wrapped, helper)))) {
        throw new Error("kill_on_expiry() requires a statically known allow-like policy");
      }

      const parent = ancestors[0];
      if (
        !parent ||
        !isCall(parent.node, "policy_for_range") ||
        parent.index !== inRangeIndex(parent.node)
      ) {
        throw new Error(
          "kill_on_expiry() may only be used as the in-range policy of policy_for_range()",
        );
      }

      // From the policy_for_range() call upwards, every step must be a ternary
      // branch (not its condition).
      for (let i = 1; i < ancestors.length; i++) {
        const step = ancestors[i];
        const below = ancestors[i - 1].node;
        const isBranch =
          step.node.op === "?:" && (step.node.args[1] === below || step.node.args[2] === below);
        if (!isBranch) {
          throw new Error(
            "a policy_for_range() using kill_on_expiry() must produce the rule's result",
          );
        }
      }
    }

    if (node.op === "call") {
      node.args[1].forEach((arg: any, index: number) =>
        walk(arg, [{ node, index }, ...ancestors]),
      );
    } else if (node.op === "rcall") {
      walk(node.args[1], [{ node, index: -1 }, ...ancestors]);
      node.args[2].forEach((arg: any, index: number) =>
        walk(arg, [{ node, index }, ...ancestors]),
      );
    } else if (Array.isArray(node.args)) {
      node.args.forEach((arg: any, index: number) =>
        walk(arg, [{ node, index }, ...ancestors]),
      );
    } else {
      walk(node.args, [{ node, index: 0 }, ...ancestors]);
    }
  })(ast, []);
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

// Functions whose value depends on when the expression runs. A cached result
// would go stale at the next midnight for today(), immediately for now(), and
// at the window's edge for policy_for_range(). Such expressions are not cached.
const TIME_DEPENDENT_CALLS = ["today", "now", "policy_for_range"];

function isCacheable(identifiers: Set<string>, calls: Set<string>): boolean {
  if (TIME_DEPENDENT_CALLS.some((name) => calls.has(name))) return false;
  return !VARIABLES.some((v) => v.dynamic && identifiers.has(v.name));
}

export interface EvalResult {
  valid: boolean;
  value?: string;
  cacheable?: boolean;
  isV2?: boolean;
  // Set when the context pinned the clock with the playground-only `now` key.
  evaluatedAt?: Date;
  // Set when policy_for_range() matched an open window with kill_on_expiry().
  pendingKill?: PendingKill;
  error?: string;
}

const celEnv = buildEnvironment();

export function evaluate(expression: string, yamlInput: string): EvalResult {
  try {
    const parsed = parseYAML(yamlInput);
    if (typeof parsed !== "object" || parsed === null) {
      return { valid: false, error: "YAML input must be a mapping" };
    }

    const pinned = clockFromContext(parsed);
    const ctx = prepareContext(parsed);
    const evalFn = celEnv.parse(expression);
    const { identifiers, calls } = analyzeAST(evalFn.ast);
    validateTimeRules(evalFn.ast);

    clockOverride = pinned;
    pendingKill = undefined;
    let value: any;
    try {
      value = evalFn(ctx);
    } finally {
      clockOverride = null;
    }

    const displayValue = mapResultToName(value);
    const cacheable = isCacheable(identifiers, calls);
    const isV2 = usesV2Features(identifiers, calls);

    return {
      valid: true,
      value: displayValue,
      cacheable,
      isV2,
      evaluatedAt: pinned?.now,
      pendingKill,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { valid: false, error: message };
  }
}
