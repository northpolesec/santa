# Coding agent hooks

An AI coding agent runs commands for you, and sometimes Santa blocks one.

When it does, the agent sees only that its tool call failed with exit status
137.
It never sees why: a blocked execution is killed with `SIGKILL`, and Santa
writes its explanation to the terminal the process was launched from, which a
tool call does not have.
So the agent guesses, and usually burns several minutes and a lot of tokens
looking for a way around the block instead of telling you about it.

A hook fixes that.
After a failed tool call the hook asks Santa what it recently blocked, and if
the answer is "that binary" it hands the agent the path and the reason.

## What Santa remembers

```shell
santactl blocks
```

```
2026-09-24T17:04:03Z  /opt/homebrew/bin/uv  No matching rule  pid=41231
```

Santa keeps the last 32 executions it denied, and forgets them when the daemon
restarts.
`--since` sets how far back to look (60 seconds by default) and `--json` prints
the same thing for a script to read.
Unless you run it as root you only see blocks of your own executions.

## The hook

Save this as `~/.claude/hooks/santa-block-check.py` and make it executable.
It needs nothing but Python 3 and `santactl`.

```python
#!/usr/bin/env python3
"""Tell a coding agent when Santa was the reason its command was killed.

Run as a hook after a failed tool call. Asks santad what it blocked in the last
few seconds and, if anything, hands the agent the blocked path and the reason.
"""

import json
import subprocess
import sys

SANTACTL = "/usr/local/bin/santactl"
LOOKBACK = "30s"

INSTRUCTION = (
    "A blocked execution is killed with SIGKILL, which usually surfaces as exit status 137, "
    "and Santa's explanation goes to a terminal a tool call does not have. This is very "
    "likely why the command failed. Do not look for a way around the block. Stop and tell "
    "the user which binary was blocked and why, so they can have it approved."
)


def recent_blocks():
  """The executions Santa recently blocked, or an empty list if it blocked none."""
  try:
    result = subprocess.run([SANTACTL, "blocks", "--json", "--since", LOOKBACK],
                            capture_output=True, text=True, timeout=5, check=False)
  except (OSError, subprocess.SubprocessError):
    # No Santa installed, or it isn't answering. Either way there is nothing to report.
    return []

  if result.returncode != 0:
    return []

  try:
    return json.loads(result.stdout)
  except json.JSONDecodeError:
    return []


def message(blocks):
  lines = ["Santa blocked %d execution(s) while this command ran:" % len(blocks)]
  for block in blocks:
    lines.append("  %s - %s" % (block.get("path", "?"), block.get("reason", "?")))
  lines.append("")
  lines.append(INSTRUCTION)
  return "\n".join(lines)


def run(payload, blocks):
  """Returns what to write to (stdout, stderr) for this hook invocation."""
  if not blocks:
    return "", ""

  event = payload.get("hook_event_name")
  if event:
    # Claude Code: hand the text back as context the agent sees.
    return json.dumps(
        {"hookSpecificOutput": {"hookEventName": event, "additionalContext": message(blocks)}}), ""

  # Any other harness: plain text on stderr.
  return "", message(blocks)


def self_check():
  blocks = [{"path": "/opt/homebrew/bin/uv", "reason": "No matching rule", "pid": 123}]

  out, err = run({"hook_event_name": "PostToolUseFailure"}, blocks)
  assert not err, err
  parsed = json.loads(out)
  assert parsed["hookSpecificOutput"]["hookEventName"] == "PostToolUseFailure"
  assert "/opt/homebrew/bin/uv" in parsed["hookSpecificOutput"]["additionalContext"]
  assert "No matching rule" in parsed["hookSpecificOutput"]["additionalContext"]

  out, err = run({}, blocks)
  assert not out, out
  assert "/opt/homebrew/bin/uv" in err

  assert run({"hook_event_name": "PostToolUseFailure"}, []) == ("", "")
  assert run({}, []) == ("", "")

  print("ok")


def main():
  if "--self-check" in sys.argv:
    return self_check()

  try:
    payload = json.loads(sys.stdin.read())
  except (json.JSONDecodeError, ValueError):
    payload = {}
  if not isinstance(payload, dict):
    payload = {}

  out, err = run(payload, recent_blocks())
  if out:
    print(out)
  if err:
    print(err, file=sys.stderr)


if __name__ == "__main__":
  main()
```

`python3 santa-block-check.py --self-check` checks it before you wire it up.

The hook does not look at the exit status.
A block is only usually a 137: once it has been laundered through `make`, a
build system or a wrapper script, the status the agent sees is whatever that
wrapper chose to return.
Asking Santa on every failed command costs one quick request and says nothing
at all when Santa blocked nothing.

## Wiring it up

For Claude Code, in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUseFailure": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/santa-block-check.py",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

Other agents call hooks differently, but the script takes the same shape
everywhere: run it after a failed command, and it writes an explanation to
stderr when Santa blocked something and stays quiet when it did not.

## What it will not catch

* Blocks from before santad last restarted, or more than 32 blocks ago.
* File-access blocks and blocked USB devices. Only executions are recorded.
* A block of another user's execution, unless the hook runs as root.
