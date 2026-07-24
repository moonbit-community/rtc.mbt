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

MoonBit is installed through the official installer without a version
argument, and `moon version --all` is logged for diagnostics. The MoonBit
toolchain is intentionally not version-pinned.

The ordinary native and ASan jobs intentionally remain compatibility-range
checks against the current OpenSSL 3.x packages on the GitHub-hosted Ubuntu
22.04 runner. Updating the reproducible build requires changing the image
digest, snapshot timestamp, and all three package versions together.
