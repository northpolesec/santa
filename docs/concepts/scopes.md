---
parent: Concepts
---

# Scopes

In addition to rules, Santa can allow or block based on scopes. Currently, only
a few scopes are implemented. Scopes are evaluated after rules, with block
evaluation preceding allow.

Scopes are a broader way of allowing or blocking executions.

{: .warning }
We strongly discourage the use of scopes as they can be relatively trivial to bypass but there are some circumstances where it is the only option.

For configuration of scopes see
[configuration.md](../deployment/configuration.md).

##### Block Scopes

Scope              | Configurable
------------------ | ------------
Blocked Path Regex | Yes
Missing __PAGEZERO | Yes

##### Allow Scopes

Scope              | Configurable
------------------ | ------------
Allowed Path Regex | Yes
Not a Mach-O       | No

##### Regex Caveats

The paths covered by the allowed path and blocked path regex patterns are not
tracked. If an execution is allowed initially, then moved into a blocked
directory, Santa has no knowledge of that move. Since Santa caches decisions,
the recently moved file will continue to be allowed to execution even though
it is now within a blocked path. Going from a blocked path to an allowed path
is not largely affected.
