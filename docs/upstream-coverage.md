# Upstream acceptance ledger

The reference snapshot is fixed at
`a10cd2c18f7c4e646e83f6f00b792ef38ac3cdb2`. With
`/path/to/webrtc-rs-rtc` pointing to a checkout at that commit, run:

```sh
scripts/audit-upstream.mjs \
  --upstream /path/to/webrtc-rs-rtc \
  --write-ledger docs/upstream-coverage.json
```

The generated ledger contains one entry for every accepted upstream test,
commented TODO test, fuzz target, and integration-test file. Each item records
its exact source location, target MoonBit area, status, and local evidence.

The mapping is deliberately semantic. `mapped_to_conformance_group` means an
item has a responsible MoonBit protocol test group; it does not claim that the
Rust test was mechanically translated. Likewise, fuzz targets are mapped to
deterministic malformed-input regressions, but this does not substitute for a
continuous fuzzing job. These distinctions keep the ledger useful without
overstating the evidence.
