---
sidebar_position: 2
---

# Time Based Rules

A time based rule is a [CEL rule](/features/binary-authorization#cel) whose
expression calls `policy_for_range()`. The call returns one policy while a time
window is open and another while it is closed, so a single rule can allow an
application during working hours and block it for the rest of the week.
Wrapping the in-range policy in `kill_on_expiry()` also quits the processes
the rule allowed once the window closes.

:::info Requirements

Time Based Rules require [Workshop](https://northpole.security/) **2026.8** or
later and Santa **2026.8** or later. Workshop sets a minimum Santa version of
2026.8 on every rule that uses `policy_for_range()`, `kill_on_expiry()`,
`now()`, `weekdays()` or `today(tz)`, so hosts running an older Santa will not
receive the rule.

:::

## How It Works

```clike
policy_for_range(weekdays(), "09:00", "17:00", ALLOWLIST, BLOCKLIST)
```

The expression above allows the binary from 09:00 to 17:00, Monday through
Friday, on each host's own clock, and blocks it at any other time. Three
properties of these rules are worth knowing before writing one:

- **The call is the whole expression.** `policy_for_range()` returns a policy,
  so a bare call is a complete rule. There is no separate schedule to manage;
  the window lives in the rule, next to the identifier it applies to.

- **The host decides.** Santa evaluates the window at the moment of each
  execution using the host's clock, so a host that is offline or asleep still
  opens and closes its windows on time.

- **The result is never cached.** Any expression that calls
  `policy_for_range()` is re-evaluated on every execution. See
  [Caching](#caching).

## Window Forms

`policy_for_range()` has four forms, one per window shape. The policy
arguments are always last.

| Form | Window | Typical use |
| ---- | ------ | ----------- |
| `policy_for_range(days, start, end, policy, out_of_range_policy)` | A weekly `HH:MM` window on each host's own clock | Working hours, on-call hours, the hours a lab machine may be used |
| `policy_for_range(days, start, end, tz, policy, out_of_range_policy)` | The same window, read in the named time zone | One window fleet-wide, such as a maintenance hour in `America/New_York` |
| `policy_for_range(start_timestamp, end_timestamp, policy, out_of_range_policy)` | One fixed span between two instants | A dated exception: a migration week, an audit, a vendor's support window |
| `policy_for_range(duration, kill_on_expiry(policy))` | A span starting at the moment of the execution | Timed access, where each launch is quit some time later |

### Weekly Window

```clike
policy_for_range([1, 2, 3, 4, 5], "09:00", "17:00", ALLOWLIST, BLOCKLIST)
```

Without a time zone argument, every host reads the window on its own clock.
The day list `[1, 2, 3, 4, 5]` means Monday through Friday; `weekdays()` is
shorthand for the same list.

### Weekly Window in a Named Time Zone

```clike
policy_for_range([0, 1, 2, 3, 4, 5, 6], "01:00", "05:00", "UTC", ALLOWLIST, BLOCKLIST)
```

With a time zone argument, every host reads the same calendar, so the window
covers the same four hours everywhere. Use this form for anything that has to
line up with a change window, a market close or a batch job.

### Fixed Span

```clike
policy_for_range(timestamp("2026-09-14T00:00:00Z"), timestamp("2026-09-21T00:00:00Z"), ALLOWLIST, BLOCKLIST)
```

The start and end are absolute instants, so this form takes no day list and no
time zone. A timestamp literal already carries its offset.

### Duration

```clike
policy_for_range(duration("30m"), kill_on_expiry(ALLOWLIST))
```

The window is `[now, now + duration)`, so it is always open at the moment the
expression runs. That is why this form takes no out-of-range policy, and why
`kill_on_expiry()` is required: the form exists to set an expiry rather than
to gate a decision. The duration must be positive.

## Window Arguments

### Days

| Value | Meaning |
| ----- | ------- |
| `0` to `6` | Sunday through Saturday, matching CEL's own `getDayOfWeek()` |
| `weekdays()` | Shorthand for `[1, 2, 3, 4, 5]`, Monday through Friday |
| `[]` | A window that never opens. The out-of-range policy applies at every moment |

A day outside `0` to `6` is an error.

### Times of Day

`start` and `end` are 24-hour `"HH:MM"` strings, exactly five characters.
`"9:00"` is rejected; write `"09:00"`.

- **An end at or before the start crosses midnight.** The day list applies to
  the day the window _starts_, so `policy_for_range([5], "22:00", "06:00", ...)`
  opens Friday at 22:00 and closes Saturday at 06:00.

- **Equal start and end covers the whole day.** `"00:00", "00:00"` on all
  seven days is a window that is always open.

- **The window is half-open.** It includes the start minute and excludes the
  end minute, so back-to-back occurrences never overlap.

### Time Zones

The `tz` argument of `policy_for_range()` and `today(tz)` accepts three kinds
of value:

| Value | Resolves to |
| ----- | ----------- |
| `"local"` | The host's own time zone. This is also the default when the form takes no `tz` |
| `"America/New_York"` | Any IANA name in the host's time zone database, including `"UTC"` |
| `"+05:30"` | A fixed `[+-]HH:MM` offset from UTC |

Anything else is an error. A window follows the civil clock of its zone, so a
09:00 to 17:00 window is still 09:00 to 17:00 after a daylight saving change.
The rule never needs editing for it.

## Policies

Both policy slots accept any policy a CEL rule can return, including
`require_touchid_with_cooldown_minutes(N)` and
`require_touchid_only_with_cooldown_minutes(N)`. The out-of-range slot does not
have to block. These three combinations cover most needs:

| In range | Out of range | Effect |
| -------- | ------------ | ------ |
| `ALLOWLIST` | `BLOCKLIST` | Available during the window, blocked outside it |
| `ALLOWLIST` | `require_touchid_with_cooldown_minutes(60)` | Available during the window, needs Touch ID outside it |
| `ALLOWLIST` | `AUDIT` | Always available, with out-of-hours executions flagged as audit matches |

`kill_on_expiry()` is narrower. It accepts only policies that let a process
start, because a blocked execution leaves nothing to quit: `ALLOWLIST`,
`AUDIT`, `SEATBELT`, `REQUIRE_TOUCHID`, `REQUIRE_TOUCHID_ONLY`,
`require_touchid_with_cooldown_minutes(N)` and
`require_touchid_only_with_cooldown_minutes(N)`. The wrapped policy must be
written out in the call; a computed policy, such as a ternary inside
`kill_on_expiry()`, is refused.

:::note

A rule that can return `SEATBELT` must carry a seatbelt policy, window or no
window.

:::

## Quitting Processes When the Window Closes {#kill-on-expiry}

Without `kill_on_expiry()`, a window governs new executions only. A process
that started inside the window keeps running after the window closes, until
the user quits it. Wrapping the in-range policy closes that gap:

```clike
policy_for_range(weekdays(), "09:00", "17:00", kill_on_expiry(ALLOWLIST), BLOCKLIST)
```

### What Santa Records

Every execution the rule allows while the window is open is recorded against
that rule, along with the deadline the window ends at. Nothing else is
recorded: a process that started before the rule arrived, or that was allowed
by a different rule, is never on the list. This is why time based rules are
never cached. A cached decision would let a process start unrecorded, and so
never be quit.

All the executions recorded under one rule share the **earliest** deadline
recorded for it. A rule has one deadline, not one per launch, and a later
launch never pushes it out. With a weekly or fixed window every execution ends
at the same instant anyway. A countdown is where this shows: launch an app at
10:00 under a 30 minute duration, launch it again at 10:20, and both processes
are quit at 10:30.

Recording requires a rule id assigned by the sync server, so a rule added
locally with `santactl` or through `StaticRules` evaluates its window but never
records a quit.

### The Warning Notification

Santa warns the user before the deadline. The lead time is 10% of the window's
length, clamped to at least 5 minutes and at most an hour:

| Window | Warning |
| ------ | ------- |
| 8 hours | 48 minutes before the deadline |
| 1 hour | 6 minutes before the deadline |
| 30 minutes | 5 minutes before the deadline |
| Under 5 minutes | At launch |

The notification reads `"<App>" will quit at 5:00 PM.` and lists the
application, its publisher, the user and the window it came from, rendered as
`9:00 AM to 5:00 PM, Mon through Fri` with the time zone appended when the rule
named one. **More Details** adds the path, Signing ID, CDHash and parent
process, and **Copy Details** puts all of it on the clipboard for a support
ticket.

The notification appears once per deadline, and only when a recorded process
is still running.

### At the Deadline

Santa sends `SIGTERM` to every recorded process, waits 5 seconds, then sends
`SIGKILL` to whatever is still running. Each signal is delivered to the
recorded execution alone; its process group is deliberately not signaled, so a
child it spawned survives unless that child was recorded under the rule in its
own right.

### What Can Change a Pending Quit

- **A window that is open again defers.** If the rule's window is standing open
  at the deadline, which happens with a 24-hour window or two back-to-back
  occurrences, the deadline moves to the end of the occurrence standing there
  and nothing is quit. A Mac that slept through a deadline wakes into the same
  behavior.

- **Pending quits survive a restart.** They are persisted, so a daemon restart
  or a reboot keeps the deadline. Santa quits anything that came due while it
  was down and re-arms the rest. Processes recorded before a reboot are gone
  with it, but a launch after the reboot under the same rule joins the
  persisted deadline.

- **Editing or deleting the rule cancels its pending quit.** The rule is
  re-checked at the warning and again at the deadline. The next execution under
  the edited rule records a fresh deadline.

- **Moving the clock backwards does not help.** Santa judges every window
  against a clock that only moves forward, so a rolled-back system clock cannot
  reopen a closed window or push out a pending quit.

## Examples

The [CEL cookbook](/cookbook/cel) has ready-to-use time based rules, each with
a link to try it in the [CEL Playground](/cookbook/cel-playground):

- [Allow an app only during working hours](/cookbook/cel#working-hours)
- [Working hours with Touch ID outside them](/cookbook/cel#working-hours-touchid)
- [Audit out-of-hours use before enforcing](/cookbook/cel#audit-before-enforcing)
- [One maintenance window for the whole fleet](/cookbook/cel#fleet-maintenance-window)
- [Quit an app when the shift ends](/cookbook/cel#quit-at-end-of-shift)
- [Timed access counted from launch](/cookbook/cel#timed-access)

## Validation

Santa compiles every CEL rule when it is added and rejects one whose expression
does not compile, so the `kill_on_expiry()` misuses below are refused on the
host.

| Expression | Why it is refused |
| ---------- | ----------------- |
| `policy_for_range(duration("30m"), ALLOWLIST)` | The duration form exists to expire access, so it requires `kill_on_expiry()` |
| `kill_on_expiry(ALLOWLIST)` on its own | The wrapper is valid only as the in-range policy of `policy_for_range()` |
| `kill_on_expiry(BLOCKLIST)` | A blocked execution leaves nothing to quit |
| `kill_on_expiry()` in the out-of-range slot | Only the in-range policy can expire |
| `kill_on_expiry("-x" in args ? AUDIT : ALLOWLIST)` | The wrapped policy must be written out, not computed |
| `policy_for_range(...) && euid == 0` | The call returns a policy, not a bool. Use a ternary |
| One `policy_for_range()` inside another's arguments | CEL evaluates every argument, so the inner window would record a quit for executions it never decided. Use a ternary |

Malformed window arguments such as `"9:00"`, `"24:00"`, `[7]` or
`"Mars/Olympus"` compile but fail when evaluated. Santa logs the failure and
skips the rule, or blocks the execution if
[`FailClosed`](/configuration/keys#FailClosed) is set.

One rule holds one window. To combine a window with another condition, put the
call in a branch of a ternary:

```clike
"--beta" in args ? policy_for_range(duration("30m"), kill_on_expiry(ALLOWLIST)) : ALLOWLIST
```

## Caching

Santa normally caches a CEL decision per binary. Any expression that calls
`policy_for_range()` is marked non-cacheable and is re-evaluated on every
execution, which is what lets a window turn over and what makes the recording
behind `kill_on_expiry()` complete. `now()` and `today()` have the same effect
for the same reason.

The cost is one CEL evaluation per execution of the binaries the rule covers,
so prefer a narrow identifier over a broad one for frequently executed
binaries.

## Troubleshooting

The daemon logs every step of a pending quit:

```sh
/usr/bin/log stream --level debug --predicate 'sender == "com.northpolesec.santa.daemon"'
```

| Log line | Meaning |
| -------- | ------- |
| `Recorded timed rule kill for <id>: quitting at <t>, warning at <t>` | The first execution under the rule was recorded |
| `Recorded execution under timed rule kill for <id> (pid ...)` | A later execution joined the same deadline |
| `Sending timed rule kill banner for <app> (<id>), quitting at <t>` | The warning notification went to the GUI |
| `Timed rule kill firing for <id>: N recorded process(es)` | The deadline arrived and N processes are being quit |
| `Timed rule kill for <id> deferred: its window is open again until <t>, nothing quit` | The window was standing open at the deadline |
| `Timed rule kill for <id> cancelled: the rule is gone` | The rule was deleted before the deadline |
| `Timed rule kill for <id> cancelled: the rule changed (rule id X -> Y)` | The rule was edited before the deadline |
| `Ignoring timed rule kill for <id>: no server-assigned rule id` | The rule was added locally, so no quit can be recorded |
| `Restored N pending timed rule kill(s)` | Pending quits were reloaded at daemon start |

## Best Practices

- **Audit before you enforce.** Ship the rule with `AUDIT` in the out-of-range
  slot, read the events for a week, then change it to `BLOCKLIST`.

- **Pick the time zone deliberately.** Leave `tz` off for anything that means
  "the working day", and name a zone for anything that has to be the same
  instant everywhere.

- **Reach for Touch ID before a hard block.** An out-of-range
  `require_touchid_with_cooldown_minutes(N)` keeps the exception path open, and
  every use is still recorded.

- **Warn people before you quit their work.** `kill_on_expiry()` on a short
  window gives a short warning. A window of an hour or more gives users real
  notice.

- **Scope by code signing identity.** As with any rule, a CDHash, Signing ID or
  Team ID identifier is much harder to sidestep than a binary path.

- **Roll out by tag.** Scope the rule to one tag first. Hosts on Santa older
  than 2026.8 silently do not receive it, so confirm your fleet's versions
  before relying on a window for coverage.
