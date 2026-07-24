#!/usr/bin/env node

/** Verify the pinned webrtc-rs/rtc acceptance inventory. */

import {
  mkdirSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";

const EXPECTED_COMMIT = "a10cd2c18f7c4e646e83f6f00b792ef38ac3cdb2";
const EXPECTED = {
  rust_tests: 1174,
  commented_todo_tests: 2,
  fuzz_targets: 87,
  root_integration_files: 32,
  crate_integration_files: 4,
};
const LEDGER_SCHEMA_VERSION = 1;
const TEST_ATTRIBUTE = /^\s*#\[(?:tokio::)?test\]\s*$/;
const FUNCTION_NAME =
  /^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)/;
const AREA_BY_ROOT = {
  "rtc-datachannel": "datachannel",
  "rtc-dtls": "dtls",
  "rtc-ice": "ice",
  "rtc-interceptor": "interceptor",
  "rtc-mdns": "mdns",
  "rtc-media": "media",
  "rtc-rtcp": "rtcp",
  "rtc-rtp": "rtp",
  "rtc-sctp": "sctp",
  "rtc-sdp": "sdp",
  "rtc-shared": "foundation",
  "rtc-srtp": "srtp",
  "rtc-stun": "stun",
  "rtc-turn": "turn",
  src: "peer_connection",
  tests: "integration",
};
const AREA_PATHS = {
  datachannel: ["datachannel"],
  dtls: ["dtls"],
  ice: ["ice"],
  interceptor: ["interceptor"],
  mdns: ["mdns"],
  media: ["media"],
  rtcp: ["rtcp"],
  rtp: ["rtp"],
  sctp: ["sctp"],
  sdp: ["sdp"],
  foundation: [
    "transport",
    "internal/codec",
    "internal/crypto",
    "internal/replay",
  ],
  srtp: ["srtp"],
  stun: ["stun"],
  turn: ["turn"],
  peer_connection: ["."],
  integration: [".", "runtime/async"],
};

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIRECTORY = dirname(SCRIPT_PATH);
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");

class AuditError extends Error {}

function splitLines(text) {
  if (text === "") {
    return [];
  }
  return text.replace(/\r?\n$/, "").split(/\r?\n/);
}

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function isDirectory(path) {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function git(root, ...arguments_) {
  let check = true;
  const finalArgument = arguments_.at(-1);
  if (
    finalArgument !== null &&
    typeof finalArgument === "object" &&
    !Array.isArray(finalArgument)
  ) {
    ({ check = true } = arguments_.pop());
  }
  const result = spawnSync("git", ["-C", root, ...arguments_], {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.error) {
    throw new AuditError(result.error.message);
  }
  if (check && result.status !== 0) {
    throw new AuditError(
      (result.stderr ?? "").trim() || (result.stdout ?? "").trim(),
    );
  }
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function gitText(root, ...arguments_) {
  return git(root, ...arguments_).stdout;
}

function gitFile(root, path) {
  return gitText(root, "show", `${EXPECTED_COMMIT}:${path}`);
}

function grepCount(root, pattern) {
  const result = git(
    root,
    "grep",
    "-n",
    "-E",
    pattern,
    EXPECTED_COMMIT,
    "--",
    "*.rs",
    { check: false },
  );
  if (result.status !== 0 && result.status !== 1) {
    throw new AuditError(result.stderr.trim());
  }
  return splitLines(result.stdout).length;
}

function inventory(root) {
  const head = gitText(root, "rev-parse", "HEAD").trim();
  if (head !== EXPECTED_COMMIT) {
    throw new AuditError(
      `upstream HEAD is ${head}; expected pinned commit ${EXPECTED_COMMIT}`,
    );
  }
  const paths = splitLines(
    gitText(root, "ls-tree", "-r", "--name-only", EXPECTED_COMMIT),
  );
  const plainTests = grepCount(root, "^[[:space:]]*#\\[test\\]");
  const asyncTests = grepCount(
    root,
    "^[[:space:]]*#\\[tokio::test\\]",
  );
  const todoTests = grepCount(
    root,
    "(//|/\\*)[[:space:]]*TODO:[[:space:]]*#\\[(tokio::)?test\\]",
  );
  const fuzzPaths = paths.filter((path) =>
    /^[^/]+\/fuzz\/fuzz_targets\/[^/]+\.rs$/.test(path),
  );
  const rootIntegration = paths.filter((path) =>
    /^tests\/[^/]+\.rs$/.test(path),
  );
  const crateIntegration = paths.filter((path) =>
    /^rtc-[^/]+\/tests\/[^/]+\.rs$/.test(path),
  );
  return {
    commit: head,
    plain_tests: plainTests,
    async_tests: asyncTests,
    rust_tests: plainTests + asyncTests,
    commented_todo_tests: todoTests,
    fuzz_targets: fuzzPaths.length,
    root_integration_files: rootIntegration.length,
    crate_integration_files: crateIntegration.length,
  };
}

function rustTestItems(root, paths) {
  const items = [];
  for (const path of paths) {
    if (!path.endsWith(".rs")) {
      continue;
    }
    const lines = splitLines(gitFile(root, path));
    for (let index = 0; index < lines.length; index += 1) {
      if (!TEST_ATTRIBUTE.test(lines[index])) {
        continue;
      }
      let name = null;
      for (
        let followingIndex = index + 1;
        followingIndex < Math.min(index + 41, lines.length);
        followingIndex += 1
      ) {
        const matched = FUNCTION_NAME.exec(lines[followingIndex]);
        if (matched !== null) {
          name = matched[1];
          break;
        }
      }
      const lineNumber = index + 1;
      items.push({
        id: `rust_test:${path}:${lineNumber}`,
        kind: "rust_test",
        upstream_path: path,
        upstream_line: lineNumber,
        name: name ?? `test_at_line_${lineNumber}`,
      });
    }
  }
  return items;
}

function splitGitGrepLine(line) {
  const fields = [];
  let start = 0;
  for (let index = 0; index < line.length && fields.length < 3; index += 1) {
    if (line[index] === ":") {
      fields.push(line.slice(start, index));
      start = index + 1;
    }
  }
  fields.push(line.slice(start));
  if (fields.length !== 4) {
    throw new AuditError(`unexpected git grep output: ${line}`);
  }
  return fields;
}

function todoTestItems(root) {
  const result = git(
    root,
    "grep",
    "-n",
    "-E",
    "(//|/\\*)[[:space:]]*TODO:[[:space:]]*#\\[(tokio::)?test\\]",
    EXPECTED_COMMIT,
    "--",
    "*.rs",
    { check: false },
  );
  if (result.status !== 0 && result.status !== 1) {
    throw new AuditError(result.stderr.trim());
  }
  return splitLines(result.stdout).map((line) => {
    const [, path, lineNumber, text] = splitGitGrepLine(line);
    return {
      id: `commented_todo_test:${path}:${lineNumber}`,
      kind: "commented_todo_test",
      upstream_path: path,
      upstream_line: Number.parseInt(lineNumber, 10),
      name: text.trim(),
    };
  });
}

function collectMbtFiles(directory, recursive, result) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === "_build" || entry.name === ".mooncakes") {
      continue;
    }
    const path = join(directory, entry.name);
    if (entry.isFile() && entry.name.endsWith(".mbt")) {
      result.push(path);
    } else if (recursive && entry.isDirectory()) {
      collectMbtFiles(path, true, result);
    }
  }
}

function toPosix(path) {
  return path.split(sep).join("/");
}

function localEvidence(repo) {
  const evidence = {};
  for (const [area, roots] of Object.entries(AREA_PATHS)) {
    const files = new Set();
    for (const relativeRoot of roots) {
      const base =
        relativeRoot === "." ? repo : join(repo, relativeRoot);
      if (!isDirectory(base)) {
        continue;
      }
      const candidates = [];
      collectMbtFiles(base, relativeRoot !== ".", candidates);
      for (const path of candidates) {
        const relativePath = relative(repo, path);
        const parts = relativePath.split(sep);
        if (parts.includes("_build") || parts.includes(".mooncakes")) {
          continue;
        }
        const name = basename(path);
        if (
          name.endsWith("_test.mbt") ||
          name.endsWith("_wbtest.mbt")
        ) {
          files.add(toPosix(relativePath));
        }
      }
    }
    if (area === "integration") {
      for (const interopName of [
        "scripts/test-rust-interop",
        "scripts/test-chromium-interop",
        "scripts/test-coturn-interop",
      ]) {
        const interop = join(repo, interopName);
        if (isFile(interop)) {
          files.add(toPosix(relative(repo, interop)));
        }
      }
    }
    evidence[area] = [...files].sort();
  }
  return evidence;
}

function classifyArea(path) {
  return AREA_BY_ROOT[path.split("/", 1)[0]] ?? "unmapped";
}

function attachMapping(item, evidence) {
  const area = classifyArea(item.upstream_path);
  let status;
  if (item.kind === "commented_todo_test") {
    status = "upstream_todo_not_in_acceptance_count";
  } else if (item.kind === "fuzz_target") {
    status = "mapped_to_malformed_input_regressions";
  } else if (
    item.kind === "root_integration_file" ||
    item.kind === "crate_integration_file"
  ) {
    status = "mapped_to_virtual_network_or_interop";
  } else if (area === "unmapped") {
    status = "unmapped";
  } else {
    status = "mapped_to_conformance_group";
  }
  return {
    ...item,
    target_area: area,
    status,
    moonbit_evidence: evidence[area] ?? [],
  };
}

function counts(items, field) {
  const result = {};
  for (const item of items) {
    result[item[field]] = (result[item[field]] ?? 0) + 1;
  }
  return result;
}

function sortedObject(value) {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) =>
      left.localeCompare(right, "en"),
    ),
  );
}

function sameCounts(actual, expected) {
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  return (
    actualKeys.length === expectedKeys.length &&
    actualKeys.every(
      (key, index) =>
        key === expectedKeys[index] && actual[key] === expected[key],
    )
  );
}

function acceptanceLedger(upstream, repo) {
  const summary = inventory(upstream);
  const paths = splitLines(
    gitText(
      upstream,
      "ls-tree",
      "-r",
      "--name-only",
      EXPECTED_COMMIT,
    ),
  );
  const items = rustTestItems(upstream, paths);
  items.push(...todoTestItems(upstream));
  for (const path of paths) {
    if (/^[^/]+\/fuzz\/fuzz_targets\/[^/]+\.rs$/.test(path)) {
      items.push({
        id: `fuzz_target:${path}`,
        kind: "fuzz_target",
        upstream_path: path,
        name: basename(path, extname(path)),
      });
    } else if (/^tests\/[^/]+\.rs$/.test(path)) {
      items.push({
        id: `root_integration_file:${path}`,
        kind: "root_integration_file",
        upstream_path: path,
        name: basename(path, extname(path)),
      });
    } else if (/^rtc-[^/]+\/tests\/[^/]+\.rs$/.test(path)) {
      items.push({
        id: `crate_integration_file:${path}`,
        kind: "crate_integration_file",
        upstream_path: path,
        name: basename(path, extname(path)),
      });
    }
  }
  const evidence = localEvidence(repo);
  const mapped = items.map((item) => attachMapping(item, evidence));
  const kindCounts = counts(mapped, "kind");
  const statusCounts = counts(mapped, "status");
  const expectedKindCounts = {
    rust_test: EXPECTED.rust_tests,
    commented_todo_test: EXPECTED.commented_todo_tests,
    fuzz_target: EXPECTED.fuzz_targets,
    root_integration_file: EXPECTED.root_integration_files,
    crate_integration_file: EXPECTED.crate_integration_files,
  };
  if (!sameCounts(kindCounts, expectedKindCounts)) {
    throw new AuditError(
      "detailed ledger counts differ from the pinned inventory: " +
        `expected ${JSON.stringify(expectedKindCounts)}, ` +
        `found ${JSON.stringify(kindCounts)}`,
    );
  }
  return {
    schema_version: LEDGER_SCHEMA_VERSION,
    upstream_commit: EXPECTED_COMMIT,
    inventory: summary,
    item_count: mapped.length,
    kind_counts: sortedObject(kindCounts),
    status_counts: sortedObject(statusCounts),
    status_semantics: {
      mapped_to_conformance_group:
        "The upstream item is assigned to a MoonBit protocol test group; " +
        "this is semantic traceability, not a source-for-source test port.",
      mapped_to_malformed_input_regressions:
        "The fuzz target is assigned to deterministic malformed-input " +
        "tests; continuous fuzz execution remains a separate CI concern.",
      mapped_to_virtual_network_or_interop:
        "The integration file is assigned to deterministic virtual-network " +
        "tests or the fixed Rust interoperability harness.",
      upstream_todo_not_in_acceptance_count:
        "The commented upstream TODO is recorded but excluded from the " +
        "1,174 valid-test acceptance count.",
      unmapped: "No MoonBit conformance area has been assigned.",
    },
    items: mapped,
  };
}

function sortJson(value) {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (value !== null && typeof value === "object") {
    const result = {};
    for (const key of Object.keys(value).sort()) {
      result[key] = sortJson(value[key]);
    }
    return result;
  }
  return value;
}

function jsonDumps(value) {
  return JSON.stringify(sortJson(value), null, 2).replace(
    /[\u007f-\uffff]/g,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function printHelp() {
  console.log(`usage: audit-upstream.mjs [--upstream UPSTREAM] [--json]
                          [--write-ledger WRITE_LEDGER]

options:
  -h, --help            show this help message and exit
  --upstream UPSTREAM
  --json
  --write-ledger WRITE_LEDGER
                        write the per-item acceptance ledger as JSON`);
}

function optionValue(arguments_, index, name) {
  const argument = arguments_[index];
  const prefix = `${name}=`;
  if (argument.startsWith(prefix)) {
    return { value: argument.slice(prefix.length), consumed: 0 };
  }
  if (argument === name) {
    if (index + 1 >= arguments_.length) {
      throw new AuditError(`argument ${name}: expected one argument`);
    }
    return { value: arguments_[index + 1], consumed: 1 };
  }
  return null;
}

function parseArguments(arguments_) {
  const parsed = {
    upstream: resolve(SCRIPT_DIRECTORY, "..", "..", "rtc"),
    json: false,
    writeLedger: null,
    help: false,
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "-h" || argument === "--help") {
      parsed.help = true;
      continue;
    }
    const upstream = optionValue(arguments_, index, "--upstream");
    if (upstream !== null) {
      parsed.upstream = resolve(upstream.value);
      index += upstream.consumed;
      continue;
    }
    const writeLedger = optionValue(
      arguments_,
      index,
      "--write-ledger",
    );
    if (writeLedger !== null) {
      parsed.writeLedger = writeLedger.value;
      index += writeLedger.consumed;
      continue;
    }
    if (argument === "--json") {
      parsed.json = true;
      continue;
    }
    throw new AuditError(`unrecognized argument: ${argument}`);
  }
  return parsed;
}

function main(arguments_) {
  const parsed = parseArguments(arguments_);
  if (parsed.help) {
    printHelp();
    return 0;
  }
  const upstream = resolve(parsed.upstream);
  const result = inventory(upstream);
  const mismatches = Object.entries(EXPECTED)
    .filter(([key, expected]) => result[key] !== expected)
    .map(([key, expected]) => [key, expected, result[key]]);
  if (parsed.json) {
    console.log(jsonDumps(result));
  } else {
    console.log(`commit: ${result.commit}`);
    console.log(
      `Rust tests: ${result.rust_tests} ` +
        `(${result.plain_tests} #[test] + ` +
        `${result.async_tests} #[tokio::test])`,
    );
    console.log(
      `commented TODO tests: ${result.commented_todo_tests}`,
    );
    console.log(`fuzz targets: ${result.fuzz_targets}`);
    console.log(
      `root integration files: ${result.root_integration_files}`,
    );
    console.log(
      `crate integration files: ${result.crate_integration_files}`,
    );
  }
  if (mismatches.length > 0) {
    for (const [key, expected, actual] of mismatches) {
      console.log(
        `mismatch: ${key}: expected ${expected}, found ${actual}`,
      );
    }
    return 1;
  }
  if (parsed.writeLedger !== null) {
    const ledger = acceptanceLedger(upstream, REPOSITORY_ROOT);
    const output = isAbsolute(parsed.writeLedger)
      ? parsed.writeLedger
      : join(REPOSITORY_ROOT, parsed.writeLedger);
    mkdirSync(dirname(output), { recursive: true });
    writeFileSync(output, `${jsonDumps(ledger)}\n`, "utf8");
    console.log(
      `wrote ${ledger.item_count} ledger items to ${resolve(output)}`,
    );
  }
  console.log("upstream commit and acceptance inventory match expected values");
  return 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.log(`error: ${message}`);
  process.exitCode = 2;
}
