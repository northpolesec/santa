// Time window math for policy_for_range(), today() and today(tz), ported from
// Source/common/cel/PolicyForRangeFunction.mm so the playground answers the way
// santad does. Instants are Dates; zones are either a fixed offset from UTC or
// an IANA name resolved through Intl.

export type Zone =
  | { kind: "fixed"; offsetSeconds: number }
  | { kind: "iana"; name: string };

export const UTC: Zone = { kind: "fixed", offsetSeconds: 0 };

export function fixedZone(offsetSeconds: number): Zone {
  return { kind: "fixed", offsetSeconds };
}

const SECOND = 1000;
const MINUTE = 60 * SECOND;

// Strict 24-hour "HH:MM": exactly five characters, four digits and a colon, with
// the hour and minute in range. Returns minutes after midnight.
export function parseHourMinute(time: string): number | null {
  if (time.length !== 5 || time[2] !== ":") return null;
  for (const index of [0, 1, 3, 4]) {
    const code = time.charCodeAt(index);
    if (code < 48 || code > 57) return null;
  }
  const hour = Number(time.slice(0, 2));
  const minute = Number(time.slice(3, 5));
  if (hour > 23 || minute > 59) return null;
  return hour * 60 + minute;
}

// Strict "[+-]HH:MM" fixed offset, returned as seconds east of UTC.
export function parseFixedOffsetSeconds(zone: string): number | null {
  if (zone.length !== 6 || (zone[0] !== "+" && zone[0] !== "-")) return null;
  const minutes = parseHourMinute(zone.slice(1));
  if (minutes === null) return null;
  return zone[0] === "-" ? -minutes * 60 : minutes * 60;
}

function ianaZoneExists(name: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: name });
    return true;
  } catch {
    return false;
  }
}

// "local" is the given local zone, [+-]HH:MM is a fixed offset, and anything
// else must be a zone name Intl accepts. Names holding a colon or ".." or
// starting with "/" are refused first, matching santad's zone loader guard.
export function resolveZone(zone: string, local: Zone): Zone {
  if (zone === "local") return local;

  const offset = parseFixedOffsetSeconds(zone);
  if (offset !== null) return fixedZone(offset);

  if (
    zone.length > 0 &&
    !zone.includes(":") &&
    !zone.startsWith("/") &&
    !zone.includes("..") &&
    ianaZoneExists(zone)
  ) {
    return { kind: "iana", name: zone };
  }

  throw new Error(
    `unknown time zone '${zone}': expected "local", an IANA name such as "America/New_York", or a [+-]HH:MM offset`,
  );
}

// The zone the browser is running in.
export function browserZone(): Zone {
  const name = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return name ? { kind: "iana", name } : UTC;
}

// The zone an ISO 8601 string carries in its suffix: "Z" is UTC and a numeric
// offset is a fixed zone. Null when the string has no offset.
export function zoneFromISOOffset(iso: string): Zone | null {
  const match = /(Z|[+-]\d{2}:\d{2})$/i.exec(iso.trim());
  if (!match) return null;
  if (match[1].toUpperCase() === "Z") return UTC;
  const offset = parseFixedOffsetSeconds(match[1]);
  return offset === null ? null : fixedZone(offset);
}

export interface Civil {
  year: number;
  month: number; // 1 to 12
  day: number;
  hour: number;
  minute: number;
  second: number;
  weekday: number; // 0 = Sunday through 6 = Saturday
}

const WEEKDAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const formatters = new Map<string, Intl.DateTimeFormat>();

function formatterFor(name: string): Intl.DateTimeFormat {
  let formatter = formatters.get(name);
  if (!formatter) {
    formatter = new Intl.DateTimeFormat("en-US", {
      timeZone: name,
      hourCycle: "h23",
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "numeric",
      minute: "numeric",
      second: "numeric",
      weekday: "short",
    });
    formatters.set(name, formatter);
  }
  return formatter;
}

// The civil time an instant falls on in a zone.
export function toCivil(instant: Date, zone: Zone): Civil {
  if (zone.kind === "fixed") {
    const shifted = new Date(instant.getTime() + zone.offsetSeconds * SECOND);
    return {
      year: shifted.getUTCFullYear(),
      month: shifted.getUTCMonth() + 1,
      day: shifted.getUTCDate(),
      hour: shifted.getUTCHours(),
      minute: shifted.getUTCMinutes(),
      second: shifted.getUTCSeconds(),
      weekday: shifted.getUTCDay(),
    };
  }

  const parts = formatterFor(zone.name).formatToParts(instant);
  const part = (type: Intl.DateTimeFormatPartTypes) =>
    parts.find((p) => p.type === type)?.value ?? "";
  return {
    year: Number(part("year")),
    month: Number(part("month")),
    day: Number(part("day")),
    hour: Number(part("hour")) % 24,
    minute: Number(part("minute")),
    second: Number(part("second")),
    weekday: WEEKDAY_NAMES.indexOf(part("weekday")),
  };
}

// Seconds east of UTC that a zone is at a given instant.
function offsetSecondsAt(instant: Date, zone: Zone): number {
  if (zone.kind === "fixed") return zone.offsetSeconds;
  const wholeSeconds = Math.floor(instant.getTime() / SECOND) * SECOND;
  const civil = toCivil(new Date(wholeSeconds), zone);
  const asUTC = Date.UTC(civil.year, civil.month - 1, civil.day, civil.hour, civil.minute, civil.second);
  return (asUTC - wholeSeconds) / SECOND;
}

// The instant a civil time falls on in a zone. Day and month values outside
// their ranges roll over the way Date.UTC rolls them, so callers can add to a
// day without their own calendar arithmetic. A civil time that a DST change
// repeats resolves to its first occurrence; one it skips resolves to the
// instant of the transition. This matches absl::FromCivil, which santad uses.
export function fromCivil(civil: Omit<Civil, "weekday">, zone: Zone): Date {
  const asUTC = Date.UTC(civil.year, civil.month - 1, civil.day, civil.hour, civil.minute, civil.second);
  if (zone.kind === "fixed") return new Date(asUTC - zone.offsetSeconds * SECOND);

  // Two passes: read the offset at the UTC-shaped instant, then again at the
  // result, which lands on the right side of any transition in between.
  const guess = asUTC - offsetSecondsAt(new Date(asUTC), zone) * SECOND;
  const refined = asUTC - offsetSecondsAt(new Date(guess), zone) * SECOND;
  return new Date(refined);
}

// Day of week of a civil date, independent of zone.
function weekdayOf(year: number, month: number, day: number): number {
  return new Date(Date.UTC(year, month - 1, day)).getUTCDay();
}

export interface WindowEval {
  inRange: boolean;
  // End of the current occurrence; set when inRange.
  windowEnd?: Date;
  // Length of that occurrence, for the notification lead.
  windowLengthMs?: number;
}

function validateDays(days: readonly (bigint | number)[]): number[] {
  return days.map((day) => {
    const value = Number(day);
    if (!Number.isInteger(value) || value < 0 || value > 6) {
      throw new Error(
        `policy_for_range() day must be 0 (Sunday) through 6 (Saturday), got ${day}`,
      );
    }
    return value;
  });
}

// A recurring HH:MM window on the listed days, read in a zone. An end at or
// before the start crosses midnight, so the occurrence containing `now` may have
// begun the day before; the day list applies to the day the window starts.
export function evalDaysHHMMWindow(
  days: readonly (bigint | number)[],
  start: string,
  end: string,
  now: Date,
  zone: Zone,
): WindowEval {
  const dayList = validateDays(days);

  const startMinutes = parseHourMinute(start);
  const endMinutes = parseHourMinute(end);
  if (startMinutes === null || endMinutes === null) {
    throw new Error(`policy_for_range() expects HH:MM times, got '${start}' and '${end}'`);
  }

  const current = toCivil(now, zone);
  const endDayOffset = endMinutes > startMinutes ? 0 : 1;

  for (const dayOffset of [0, -1]) {
    const startDay = current.day + dayOffset;
    const windowStart = fromCivil(
      {
        year: current.year,
        month: current.month,
        day: startDay,
        hour: Math.floor(startMinutes / 60),
        minute: startMinutes % 60,
        second: 0,
      },
      zone,
    );
    const windowEnd = fromCivil(
      {
        year: current.year,
        month: current.month,
        day: startDay + endDayOffset,
        hour: Math.floor(endMinutes / 60),
        minute: endMinutes % 60,
        second: 0,
      },
      zone,
    );

    if (
      windowStart.getTime() <= now.getTime() &&
      now.getTime() < windowEnd.getTime() &&
      dayList.includes(weekdayOf(current.year, current.month, startDay))
    ) {
      return {
        inRange: true,
        windowEnd,
        windowLengthMs: windowEnd.getTime() - windowStart.getTime(),
      };
    }
  }

  return { inRange: false };
}

// An absolute span [start, end).
export function evalTimestampWindow(start: Date, end: Date, now: Date): WindowEval {
  if (start.getTime() <= now.getTime() && now.getTime() < end.getTime()) {
    return { inRange: true, windowEnd: end, windowLengthMs: end.getTime() - start.getTime() };
  }
  return { inRange: false };
}

// [now, now + duration), which always contains now.
export function evalDurationWindow(durationMs: number, now: Date): WindowEval {
  return {
    inRange: true,
    windowEnd: new Date(now.getTime() + durationMs),
    windowLengthMs: durationMs,
  };
}

// How far before a window closes the user is warned: 10% of the occurrence's
// length, at least 5 minutes and at most an hour.
export function notificationLeadMs(windowLengthMs: number): number {
  return Math.min(Math.max(windowLengthMs / 10, 5 * MINUTE), 60 * MINUTE);
}
