# Code signing policy

This document explains how released copies of Form Buddy are built and signed,
and who is able to authorise a signature. SignPath Foundation requires projects
to publish this, and it is worth publishing regardless: it is the only way a
signature tells you anything useful.

## Who maintains this project

Form Buddy is developed and maintained by **Torigan**
([torigan.com](https://torigan.com)), which owns this repository and all of the
source code and build scripts in it.

## Where the binary comes from

`FormBuddy.exe` is built from [`source/FormBuddy.py`](source/FormBuddy.py) by
the workflow in [`.github/workflows/build.yml`](.github/workflows/build.yml),
running on GitHub-hosted Windows runners. Nobody builds release binaries on a
personal machine and uploads them by hand.

The build takes no inputs other than this repository and the pinned Python
packages it installs, so anyone can reproduce it by running the same command
listed in the README.

## Signing

Code signing is provided free of charge by
[SignPath Foundation](https://signpath.org), using the SignPath.io service. The
certificate is issued to Torigan and is held by SignPath; the project never
handles a private key.

- Signing requests are raised only by the automated build described above.
- Each request must be approved by a maintainer holding the **Approver** role.
- Approvers confirm that the commit being signed is a reviewed, intended
  release before approving.

## Account security

Every person with write access to this repository, and every person holding an
Approver role, has multi-factor authentication enabled.

## Privacy

Form Buddy contains no network code. It collects nothing, sends nothing and
has no telemetry of any kind. Answers are encrypted on the user's own machine
with a key derived from their password, and that password is never stored
anywhere. See the Privacy section of the [README](README.md).

The signing service is told only what any public build already reveals: the
repository, the commit, and the artefact being signed.

## What this software does, stated plainly

Form Buddy installs a global keyboard hook so it can notice the user tapping
`Alt` twice, reads the focused control through Windows UI Automation, and
synthesises keystrokes to type an answer into it. Those are the documented
Windows APIs for exactly this kind of accessibility and automation tool.

Mechanically this overlaps with what a keylogger does, and antivirus
heuristics reasonably flag it. The difference is what happens next: nothing is
recorded, nothing is stored beyond the answers the user deliberately saved,
and nothing leaves the machine. Every line of that is in the single source
file in this repository.

The program contains no feature intended to find or exploit security
vulnerabilities, and none intended to circumvent any security measure.

## Reporting a problem

Open an issue on this repository, or contact Torigan through
[torigan.com](https://torigan.com).
