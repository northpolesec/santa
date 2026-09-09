import { describe, it, expect } from "vitest";
import {
  UTC,
  fixedZone,
  parseHourMinute,
  parseFixedOffsetSeconds,
  resolveZone,
  zoneFromISOOffset,
  toCivil,
  fromCivil,
  evalDaysHHMMWindow,
  evalTimestampWindow,
  evalDurationWindow,
  notificationLeadMs,
  type Zone,
} from "./timewindow";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

// A host at UTC-4, the zone every example in the cookbook is written for.
const EDT = fixedZone(-4 * 3600);
const NEW_YORK: Zone = { kind: "iana", name: "America/New_York" };

// 2026-09-14 is a Monday, 2026-09-12 a Saturday, 2026-09-11 a Friday.
const t = (iso: string) => new Date(iso);

describe("parseHourMinute", () => {
  it.each([
    ["00:00", 0],
    ["09:00", 540],
    ["23:59", 1439],
  ])("parses %s", (s, minutes) => {
    expect(parseHourMinute(s)).toBe(minutes);
  });

  it.each(["9:00", "24:00", "09:60", "0900", "09:00:00", "ab:cd", ""])(
    "rejects %s",
    (s) => {
      expect(parseHourMinute(s)).toBeNull();
    },
  );
});

describe("parseFixedOffsetSeconds", () => {
  it.each([
    ["+05:30", 19800],
    ["-04:00", -14400],
    ["+00:00", 0],
  ])("parses %s", (s, seconds) => {
    expect(parseFixedOffsetSeconds(s)).toBe(seconds);
  });

  it.each(["+5:30", "0530", "+0530", "+24:00", "UTC", "05:30"])(
    "rejects %s",
    (s) => {
      expect(parseFixedOffsetSeconds(s)).toBeNull();
    },
  );
});

describe("resolveZone", () => {
  it("returns the local zone for 'local'", () => {
    expect(resolveZone("local", EDT)).toEqual(EDT);
  });

  it("parses a fixed offset", () => {
    expect(resolveZone("+05:30", EDT)).toEqual(fixedZone(19800));
  });

  it("accepts IANA names and UTC", () => {
    expect(resolveZone("America/New_York", EDT)).toEqual(NEW_YORK);
    expect(resolveZone("UTC", EDT).kind).toBe("iana");
  });

  it.each(["Mars/Olympus", "file:/etc/localtime", "/etc/localtime", "../zoneinfo/UTC", ""])(
    "rejects %s",
    (name) => {
      expect(() => resolveZone(name, EDT)).toThrow(/unknown time zone/);
    },
  );
});

describe("zoneFromISOOffset", () => {
  it("reads a trailing Z as UTC", () => {
    expect(zoneFromISOOffset("2026-09-14T10:30:00Z")).toEqual(UTC);
  });

  it("reads a numeric offset", () => {
    expect(zoneFromISOOffset("2026-09-14T10:30:00-04:00")).toEqual(EDT);
    expect(zoneFromISOOffset("2026-09-14T10:30:00.250+05:30")).toEqual(fixedZone(19800));
  });

  it("returns null when the string carries no offset", () => {
    expect(zoneFromISOOffset("2026-09-14T10:30:00")).toBeNull();
    expect(zoneFromISOOffset("2026-09-14")).toBeNull();
  });
});

describe("toCivil / fromCivil", () => {
  it("reads civil time in a fixed zone", () => {
    const civil = toCivil(t("2026-09-14T10:30:00Z"), fixedZone(19800));
    expect(civil).toMatchObject({ year: 2026, month: 9, day: 14, hour: 16, minute: 0, weekday: 1 });
  });

  it("reads civil time in an IANA zone, crossing the date line backwards", () => {
    // 03:30Z on Monday is 23:30 on Sunday in New York (EDT, UTC-4).
    const civil = toCivil(t("2026-09-14T03:30:00Z"), NEW_YORK);
    expect(civil).toMatchObject({ year: 2026, month: 9, day: 13, hour: 23, minute: 30, weekday: 0 });
  });

  it.each([
    ["2026-09-14T10:30:00Z", EDT],
    ["2026-09-14T10:30:00Z", NEW_YORK],
    ["2026-03-08T07:30:00Z", NEW_YORK], // the US spring-forward day
    ["2026-11-01T12:30:00Z", NEW_YORK], // the US fall-back day, after the repeated hour
    ["2026-01-15T00:00:00Z", UTC],
  ])("round-trips %s through %j", (iso, zone) => {
    const instant = t(iso);
    expect(fromCivil(toCivil(instant, zone), zone).getTime()).toBe(instant.getTime());
  });

  it("builds a New York midnight at the right UTC instant across DST", () => {
    const summer = fromCivil({ year: 2026, month: 9, day: 14, hour: 0, minute: 0, second: 0 }, NEW_YORK);
    expect(summer.toISOString()).toBe("2026-09-14T04:00:00.000Z");
    const winter = fromCivil({ year: 2026, month: 1, day: 14, hour: 0, minute: 0, second: 0 }, NEW_YORK);
    expect(winter.toISOString()).toBe("2026-01-14T05:00:00.000Z");
  });
});

describe("evalDaysHHMMWindow", () => {
  const weekdays = [1n, 2n, 3n, 4n, 5n];

  it("is in range on a weekday inside the hours", () => {
    const result = evalDaysHHMMWindow(weekdays, "09:00", "17:00", t("2026-09-14T14:30:00Z"), EDT);
    expect(result.inRange).toBe(true);
    expect(result.windowEnd?.toISOString()).toBe("2026-09-14T21:00:00.000Z");
    expect(result.windowLengthMs).toBe(8 * HOUR);
  });

  it("is out of range on a weekend", () => {
    const result = evalDaysHHMMWindow(weekdays, "09:00", "17:00", t("2026-09-12T18:00:00Z"), EDT);
    expect(result.inRange).toBe(false);
  });

  it("includes the start minute and excludes the end minute", () => {
    // 09:00 and 17:00 in EDT are 13:00Z and 21:00Z.
    expect(evalDaysHHMMWindow(weekdays, "09:00", "17:00", t("2026-09-14T13:00:00Z"), EDT).inRange).toBe(true);
    expect(evalDaysHHMMWindow(weekdays, "09:00", "17:00", t("2026-09-14T20:59:59Z"), EDT).inRange).toBe(true);
    expect(evalDaysHHMMWindow(weekdays, "09:00", "17:00", t("2026-09-14T21:00:00Z"), EDT).inRange).toBe(false);
    expect(evalDaysHHMMWindow(weekdays, "09:00", "17:00", t("2026-09-14T12:59:59Z"), EDT).inRange).toBe(false);
  });

  it("crosses midnight and applies the day list to the day the window starts", () => {
    // [5] Friday 22:00 to Saturday 06:00, read in UTC for readability.
    const friday22 = "22:00";
    const saturday06 = "06:00";
    expect(evalDaysHHMMWindow([5n], friday22, saturday06, t("2026-09-11T23:00:00Z"), UTC).inRange).toBe(true);
    expect(evalDaysHHMMWindow([5n], friday22, saturday06, t("2026-09-12T03:00:00Z"), UTC).inRange).toBe(true);
    expect(evalDaysHHMMWindow([5n], friday22, saturday06, t("2026-09-12T06:00:00Z"), UTC).inRange).toBe(false);
    expect(evalDaysHHMMWindow([5n], friday22, saturday06, t("2026-09-11T21:59:00Z"), UTC).inRange).toBe(false);
    // Saturday night is not covered: the window that would contain it starts on Saturday.
    expect(evalDaysHHMMWindow([5n], friday22, saturday06, t("2026-09-12T23:00:00Z"), UTC).inRange).toBe(false);
    const result = evalDaysHHMMWindow([5n], friday22, saturday06, t("2026-09-12T03:00:00Z"), UTC);
    expect(result.windowEnd?.toISOString()).toBe("2026-09-12T06:00:00.000Z");
    expect(result.windowLengthMs).toBe(8 * HOUR);
  });

  it("treats equal start and end as the whole day", () => {
    const everyDay = [0n, 1n, 2n, 3n, 4n, 5n, 6n];
    const result = evalDaysHHMMWindow(everyDay, "00:00", "00:00", t("2026-09-12T18:00:00Z"), UTC);
    expect(result.inRange).toBe(true);
    expect(result.windowEnd?.toISOString()).toBe("2026-09-13T00:00:00.000Z");
    expect(result.windowLengthMs).toBe(24 * HOUR);
  });

  it("never opens for an empty day list", () => {
    expect(evalDaysHHMMWindow([], "00:00", "00:00", t("2026-09-14T14:30:00Z"), UTC).inRange).toBe(false);
  });

  it("reads the window in the zone it is given, not the host's", () => {
    // 01:00 to 05:00 UTC. 03:30Z is inside it whatever the host zone would say.
    const everyDay = [0n, 1n, 2n, 3n, 4n, 5n, 6n];
    expect(evalDaysHHMMWindow(everyDay, "01:00", "05:00", t("2026-09-15T03:30:00Z"), UTC).inRange).toBe(true);
    // The same instant read in EDT is 23:30 the day before, outside the hours.
    expect(evalDaysHHMMWindow(everyDay, "01:00", "05:00", t("2026-09-15T03:30:00Z"), EDT).inRange).toBe(false);
  });

  it("follows the civil clock across a DST change", () => {
    // 09:00 New York is 13:00Z in September but 14:00Z in January.
    const everyDay = [0n, 1n, 2n, 3n, 4n, 5n, 6n];
    expect(evalDaysHHMMWindow(everyDay, "09:00", "17:00", t("2026-09-14T13:30:00Z"), NEW_YORK).inRange).toBe(true);
    expect(evalDaysHHMMWindow(everyDay, "09:00", "17:00", t("2026-01-14T13:30:00Z"), NEW_YORK).inRange).toBe(false);
    expect(evalDaysHHMMWindow(everyDay, "09:00", "17:00", t("2026-01-14T14:30:00Z"), NEW_YORK).inRange).toBe(true);
  });

  it.each([[[7n]], [[-1n]], [[1n, 9n]]])("rejects day list %s", (days) => {
    expect(() => evalDaysHHMMWindow(days, "09:00", "17:00", t("2026-09-14T14:30:00Z"), UTC)).toThrow(
      /day must be 0 \(Sunday\) through 6 \(Saturday\)/,
    );
  });

  it.each([
    ["9:00", "17:00"],
    ["09:00", "24:00"],
    ["09:00", "09:60"],
  ])("rejects malformed times %s to %s", (start, end) => {
    expect(() => evalDaysHHMMWindow([1n], start, end, t("2026-09-14T14:30:00Z"), UTC)).toThrow(
      /expects HH:MM times/,
    );
  });
});

describe("evalTimestampWindow", () => {
  const start = t("2026-09-14T00:00:00Z");
  const end = t("2026-09-21T00:00:00Z");

  it("is half open", () => {
    expect(evalTimestampWindow(start, end, start).inRange).toBe(true);
    expect(evalTimestampWindow(start, end, t("2026-09-17T12:00:00Z")).inRange).toBe(true);
    expect(evalTimestampWindow(start, end, end).inRange).toBe(false);
    expect(evalTimestampWindow(start, end, t("2026-09-13T23:59:59Z")).inRange).toBe(false);
  });

  it("reports the end and the length", () => {
    const result = evalTimestampWindow(start, end, t("2026-09-17T12:00:00Z"));
    expect(result.windowEnd).toEqual(end);
    expect(result.windowLengthMs).toBe(7 * 24 * HOUR);
  });
});

describe("evalDurationWindow", () => {
  it("is always in range and ends a duration after now", () => {
    const now = t("2026-09-14T14:00:00Z");
    const result = evalDurationWindow(30 * MINUTE, now);
    expect(result.inRange).toBe(true);
    expect(result.windowEnd?.toISOString()).toBe("2026-09-14T14:30:00.000Z");
    expect(result.windowLengthMs).toBe(30 * MINUTE);
  });
});

describe("notificationLeadMs", () => {
  it.each([
    [8 * HOUR, 48 * MINUTE],
    [1 * HOUR, 6 * MINUTE],
    [30 * MINUTE, 5 * MINUTE],
    [2 * MINUTE, 5 * MINUTE],
    [12 * HOUR, 60 * MINUTE],
    [7 * 24 * HOUR, 60 * MINUTE],
  ])("a window of %d ms warns %d ms ahead", (length, lead) => {
    expect(notificationLeadMs(length)).toBe(lead);
  });
});
