---
title: Known Limitations
nav_order: 7
---

## Known limitations

*   Santa only blocks execution (execve and variants); it doesn't protect
    against dynamic libraries loaded with dlopen, libraries on disk that have
    been replaced, or libraries loaded using `DYLD_INSERT_LIBRARIES`.

*   Scripts: Santa is written to ignore any execution that isn't a binary. After
    weighing the administrative cost versus the benefit, we found it wasn't
    worthwhile to manage the execution of scripts. Additionally, several
    applications make use of temporary scripts, and blocking these could cause
    problems. We're happy to revisit this (or at least make it an option) if it
    would be useful to others.

*   USB Mass Storage Blocking: Santa's USB Mass Storage blocking feature only
    stops incidental data exfiltration. It is not meant as a hard control. It
    cannot block:

    *   Directly writing to an unmounted, but attached device

*   Metrics reported by Santa are not currently in a format that is friendly to
    open source solutions
    ([Issue #563](https://github.com/google/santa/issues/563))

*   Standalone Mode
    *   Users will not be notified of processes that were blocked while a user
        was not logged in to the system.
    *   Fast user switching and/or logging out while an authorization dialog is
        presented to the user can sometimes result in the process being kept in a
        suspended state, preventing subsequent launches. The user must manually
        kill the affected process (e.g. `kill -9 <pid>`).
