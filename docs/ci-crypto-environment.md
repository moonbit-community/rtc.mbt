# Reproducible crypto CI environment

The `crypto-pinned` CI job fixes every layer that selects the OpenSSL build:

| Layer | Pin |
| --- | --- |
| Linux/architecture | Ubuntu 22.04, Linux x86_64 |
| OCI platform image | `ubuntu:22.04@sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8` |
| Ubuntu archive snapshot | `20260702T000000Z` |
| `openssl`, `libssl3`, `libssl-dev` | `3.0.2-0ubuntu1.25` |

The job replaces the container's APT sources with timestamped official Ubuntu
snapshot sources before installing packages. It rejects any resolved OpenSSL
package whose complete Debian version differs from the pin, runs the entire
native test suite, and archives both `dpkg-query` output and
`openssl version -a`.

Snapshot APT update and install each get at most four attempts, with 5, 10,
and 20 second delays after failures. Every attempt logs its exit status, and
the last failed command's status is preserved. APT's internal retries are
disabled; the HTTPS timeout for both connection and data inactivity is 30
seconds. Certificate verification, the timestamped sources, exact package
versions, and `APT::Update::Error-Mode=any` remain enforced. The retry function
lives in the workflow because installation runs before checkout. Crypto
identity artifacts are uploaded only after identity verification succeeds,
including when subsequent tests fail.

`python3 scripts/test-ci-snapshot-retry.py` exercises the workflow's actual
installation shell block with mock APT and sleep commands. It checks immediate
success, recovery after transient failures, update exhaustion (which must skip
install), and install exhaustion, including attempt counts, delays, options,
and final exit status. The ordinary native CI job runs this regression check.

MoonBit is installed through the official installer without a version
argument, and `moon version --all` is logged for diagnostics. The MoonBit
toolchain is intentionally not version-pinned.

The ordinary native and ASan jobs intentionally remain compatibility-range
checks against the current OpenSSL 3.x packages on the GitHub-hosted Ubuntu
22.04 runner. Updating the reproducible build requires changing the image
digest, snapshot timestamp, and all three package versions together.

The ASan job logs and archives `moon version --all`, `openssl version -a`,
`cc --version`, and the installed versions of OpenSSL, its development/runtime
packages, all `libasan*` packages, `build-essential`, GCC, and libc. Its identity
artifact is also uploaded after test failures, provided version recording
succeeded.

The real UDP and ICE TCP Driver tests keep their 60 second deadline. On
failure only, they print the transport, both candidate ports (the active TCP
candidate uses port 0), role, stage, elapsed times, and all observed errors.
Stages cover setup, negotiation, each channel opening, send/receive, close,
and Driver exit. The first observed error is recorded before task-group
cancellation and re-raised after cleanup; subsequent cancellation errors
cannot replace it. The deadline watcher records `TimeoutError` before
cancelling its siblings. These diagnostics do not establish a root cause for
the previously intermittent UDP failure.
