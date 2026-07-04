# Agent Instructions

## Overview

Santa is a macOS security enforcement tool that allows/denies binary execution based on rules.

## Structure

| Path | Purpose |
|------|---------|
| `Source/` | C++/ObjC source code |
| `Testing/` | Test suites |
| `docs/` | Documentation |
| `Conf/` | Configuration files |

## Commands

```bash
bazel build //...         # build all targets
bazel test //...          # run all tests
bazel build //:release    # build release package
```

See [CLAUDE.md](CLAUDE.md) for Claude Code configuration.
