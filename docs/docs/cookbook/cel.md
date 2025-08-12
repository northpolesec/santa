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
['--global-disable', '--master-disable','--disable', '--add', '--remove'].exists(flag, flag in args) ? BLOCKLIST : ALLOWLIST
```

## Prevent users from enabling remote access via SSH on the command line


systemsetup can be used to enable Remote Apple Events. Set whether the system responds to events sent by other computers (such as AppleScripts).



## Prevent Users from enabling remote apple events

You can use `systemsetup` can be used to enable Remote Apple Events from other
computers. This can be blocked with a CEL rule.

First set a signing ID `platform:com.apple.systemsetup`

```clike
args.exists(i, args[i] == "-setremotelogin" && 
             args[i+1:].exists(arg, arg == "on"))
```

