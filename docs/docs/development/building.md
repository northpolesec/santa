---
sidebar_position: 2
---

# Building

Santa uses [Bazel](https://bazel.build) for building, testing, and releaseing.
The `main` branch on GitHub is always the source-of-truth.

## Installing Bazelisk

To ensure everyone is building with the correct version of Bazel, we use
[Bazelisk](https://bazel.build/install/bazelisk), which automatically downloads
the appropriate version of Bazel when run.

If you don't already have bazel/bazelisk installed, you can use homebrew:

```shell
brew install bazelisk
```

This will add both `bazelisk` and `bazel` to your `PATH`.

## Cloning

```shell
git clone https://github.com/northpolesec/santa
cd santa
```

By default your checkout will be in the `main` branch, ready to start developing
at head. As all releases are built from tagged commits, you can check out
a specific release if you wish:

```
git checkout 2025.2
```

If you want to see which tags are available, you can run:

```
git tag --sort=createordate
```

## Building

To make using bazel easier we also have a simple Makefile which just invokes
useful bazel commands. To ensure your changes are formatted correctly and build,
you can run `make` in the root of the Santa repo:

```
make
```

## Testing

To run the full suite of Santa tests, you can run `make test`:

```
make test
```

## Installing

While working on Santa, it is useful to have a quick way to reload all Santa
components. For this we have a special BUILD rule to handle this and it is
exposed as the make command `make reload`.

However, because Santa is a system extension with special entitlements it is not
as trivial to load Santa on a machine that is not registered as a machine owned
by North Pole Security. To work around this, it is possible to reload an "adhoc"
build, but only if you disable SIP:

1. Boot into recvoery mode:

   - For Intel Macs, reboot and hold down `Command + R`
   - For Apple Silicon Macs, power off then press and hold the Power button
     until "Loading startup options" appears. Click Options, then Continue. If
     asked, select a volume to recover then click Next.

2. From the Utilities menu click Terminal.

3. Run `csrutil disable` to turn SIP off.

4. Reboot.

Now you can build and run an adhoc build:

```
bazel run //:reload --define=SANTA_BUILD_TYPE=adhoc
```

## IDE Setup

If you want to use an IDE when developing Santa it is much more useful if your
IDE understands the codebase to make suggestions, allow renaming variables and
following definitions. You can have Bazel generate a compiler commands file that
will let `clangd` understand Santa:

1. Run `make compile_commands`. This will generate a `compile_commands.json`
   file in the root of the workspace.

2. [Configure your
   editor](https://github.com/hedronvision/bazel-compile-commands-extractor?tab=readme-ov-file#editor-setup--for-autocomplete-based-on-compile_commandsjson)
   to use the `compile_commands.json` file for autocompletion.
