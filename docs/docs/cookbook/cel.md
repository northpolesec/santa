# Common Expression Language (CEL)

This page lists well-known and/or community-contributed CEL expressions.

CEL ([Common Expression Language](https://cel.dev/)) rules allow for more
complex policies than would normally be possible. Read how to configure CEL
rules in the [Binary Authorization](/features/binary-authorization#cel)
documentation.

## Apps signed since X

This will prevent executions of an app where the specific binary was signed
before the provided date. This is particularly useful when attached to a
`TEAMID` or `SIGNINGID` rule.

```clike
target.signing_time >= timestamp('2025-05-31T00:00:00Z')
```

## Prevent users from disabling gatekeeper

Create a signing ID rule for `platform:com.apple.spctl` and attach the following CEL program

```clike
['--global-disable', '--master-disable','--disable', '--add', '--remove'].exists(flag, flag in args) ? BLOCKLIST : ALLOWLIST
```

## Prevent Timestomping of LaunchAgents and LaunchDaemons

Malware like those produced by the Chollima groups use "timestomping" to reset the
timestamps of LaunchAgents and LaunchDaemons using touch. This can be prevented
/ detected by creating a SigningID rule for `platform:com.apple.touch` with the
following CEL program.

This technique was recently discussed by [Jaron
Bradely](https://themittenmac.com/author/jaron-bradley/) at [Objective by the
Sea v8](https://objectivebythesea.org/v8/talks.html#Speaker_24)

```clike
args.exists(arg, arg in ['-a', '-m', '-r', '-A', '-t']) && args.join(" ").contains("Library/Launch") ? BLOCKLIST : ALLOWLIST
```

Note this will not stop using the system calls directly or otherwise programmatically modifying the timestamps.
