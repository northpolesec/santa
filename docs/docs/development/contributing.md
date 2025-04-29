---
sidebar_position: 1
---

# Contributing

## Before you contribute

Before we can use your code, you must sign the [North Pole Security Individual
Contributor License Agreement](https://cla-assistant.io/northpolesec/santa)
(CLA), which you can do online. The CLA is necessary mainly because you own the
copyright to your changes even after your contribution becomes part of our
codebase, so we need your permission to use and distribute your code. We also
need to be sure of various other things—for instance that you’ll tell us if you
know that your code infringes on other people’s patents. You don’t have to sign
the CLA until after you’ve submitted your code for review and a member has
approved it, but you must do it before we can put your code into our codebase.

Before you start working on a larger contribution, you should get in touch with
us first through the [issue
tracker](https://github.com/northpolesec/santa/issues) with your idea so that we
can help out and possibly guide you. Co-ordinating large changes ahead of time
can avoid frustration later on.

## Code Reviews

All submissions - including those by project members - **require** review. We
provide feedback and comments through GitHub's normal pull request mechanism.

If you receive feedback from one of the maintainers with suggestions or
requested changes, please make the appropriate changes and _upload a new
commit_, do not force-push an amended change or rebase, as this prevents GitHub
from presenting "changes since last review".

If you receive feedback that you are uncertain about, feel free to ask for more
details, but please note that we do have limited time so it may take time for
us to respond.

## Code Style

Santa's codebase is generally written to adhere to Google's
[C++](https://google.github.io/styleguide/cppguide.html) and
[Objective-C](https://google.github.io/styleguide/objcguide.xml) style guides.
To avoid wasting time discussing the finer points of code style, we use
clang-format to enforce cohesive styling. You can run `./Testing/fix.sh` in your
workspace to automatically format your code before submitting your PR. A GitHub
action workflow will present an error if your code does not match the expected
style.
