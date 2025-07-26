# Common Expression Language (CEL)

This page lists well-known and/or community-contributed CEL expressions.

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
['--global-disable', '--disable', '--remove'].exists(flag, flag in args) ? BLOCKLIST : ALLOWLIST
```
