#!/usr/bin/env node

/**
 * Record and compare the rtc.mbt native benchmark baseline.
 *
 * The gate deliberately performs outer sampling around MoonBit's benchmark
 * harness. A comparison warms both revisions, then alternates baseline and
 * candidate runs so gradual runner drift does not consistently favor either
 * revision.
 */

import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  arch,
  constants as osConstants,
  cpus,
  tmpdir,
} from "node:os";
import { performance } from "node:perf_hooks";
import {
  dirname,
  join,
  resolve,
} from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const FORMAT_VERSION = 2;
const MIN_WARMUPS = 5;
const MIN_SAMPLES = 20;
const THRESHOLD = 0.2;
const BENCHMARK_SOURCE = "rtc_bench_test.mbt";
const BENCHMARK_COMMAND = [
  "moon",
  "bench",
  "--release",
  "--target",
  "native",
  "--no-parallelize",
  "-p",
  "moonbit-community/rtc",
  "-f",
  "rtc_bench_test.mbt",
];
const BENCHMARKS = {
  "bench SDP parse and marshal": { kind: "latency" },
  "bench STUN decode and encode": { kind: "latency" },
  "bench DTLS application-data crypto": { kind: "latency" },
  "bench SRTP protect and unprotect": { kind: "latency" },
  "bench RTP and RTCP codecs": { kind: "latency" },
  "bench SCTP reliable throughput": {
    kind: "throughput",
    workload_bytes: 16384,
  },
  "bench end-to-end PeerConnection DataChannel pipeline": {
    kind: "throughput",
    workload_bytes: 4096,
  },
};
const TIME_FACTORS = {
  ns: 1.0e-9,
  "µs": 1.0e-6,
  us: 1.0e-6,
  ms: 1.0e-3,
  s: 1.0,
};
const BENCHMARK_LINE =
  /^\[.+\] bench .+ \("(.+)"\) ok$/;
const MEAN_LINE =
  /^\s*([0-9]+(?:\.[0-9]+)?)\s*(ns|µs|us|ms|s)\s*±/;

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIRECTORY = dirname(SCRIPT_PATH);
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");

class GateError extends Error {}

let activeChild = null;
let interruptedSignal = null;

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function commandLine(arguments_) {
  return arguments_.join(" ");
}

function spawnCommand(arguments_, { cwd, environment }) {
  const [command, ...commandArguments] = arguments_;
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, commandArguments, {
      cwd,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    activeChild = child;
    let stdout = "";
    let stderr = "";
    let settled = false;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    const finish = (callback) => {
      if (settled) {
        return;
      }
      settled = true;
      if (activeChild === child) {
        activeChild = null;
      }
      callback();
    };
    child.once("error", (error) => {
      finish(() => rejectPromise(new GateError(error.message)));
    });
    child.once("close", (returncode, signal) => {
      finish(() =>
        resolvePromise({
          returncode,
          signal,
          stdout,
          stderr,
        }),
      );
    });
  });
}

async function run(
  arguments_,
  { cwd, check = true, environment = undefined },
) {
  const result = await spawnCommand(arguments_, { cwd, environment });
  if (check && result.returncode !== 0) {
    const detail =
      result.stderr.trim() || result.stdout.trim();
    throw new GateError(
      `command failed (${result.returncode ?? result.signal}): ` +
        commandLine(arguments_) +
        (detail ? `\n${detail}` : ""),
    );
  }
  return result;
}

async function git(repo, ...arguments_) {
  let check = true;
  const finalArgument = arguments_.at(-1);
  if (
    finalArgument !== null &&
    typeof finalArgument === "object" &&
    !Array.isArray(finalArgument)
  ) {
    ({ check = true } = arguments_.pop());
  }
  const result = await run(["git", ...arguments_], {
    cwd: repo,
    check,
  });
  return result.stdout.trim();
}

async function committedRevision(repo, { allowDirty }) {
  const revision = await git(repo, "rev-parse", "--verify", "HEAD");
  const dirty = Boolean(await git(repo, "status", "--short"));
  if (dirty && !allowDirty) {
    throw new GateError(
      "the benchmark tree is dirty; commit it first or pass --allow-dirty",
    );
  }
  return { revision, dirty };
}

function fileSha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function machineArchitecture() {
  return (
    {
      x64: "x86_64",
      arm64: "aarch64",
      ia32: "i686",
    }[arch()] ?? arch()
  );
}

function cpuModel() {
  const cpuinfo = "/proc/cpuinfo";
  if (isFile(cpuinfo)) {
    for (const line of readFileSync(cpuinfo, "utf8").split(/\r?\n/)) {
      if (
        line.toLowerCase().startsWith("model name") &&
        line.includes(":")
      ) {
        return line.slice(line.indexOf(":") + 1).trim();
      }
    }
  }
  return cpus()[0]?.model || "unknown";
}

function runnerFingerprint() {
  return {
    runner_id: process.env.RTC_BENCH_RUNNER_ID ?? "",
    machine: machineArchitecture(),
    cpu_model: cpuModel(),
  };
}

function reprString(value) {
  return `'${String(value)
    .replaceAll("\\", "\\\\")
    .replaceAll("'", "\\'")}'`;
}

function checkRunner(expected, actual) {
  const fields = ["machine", "cpu_model"];
  if (expected.runner_id) {
    fields.push("runner_id");
  }
  const mismatches = fields
    .filter((field) => expected[field] !== actual[field])
    .map(
      (field) =>
        `${field}: baseline=${reprString(expected[field])}, ` +
        `candidate=${reprString(actual[field])}`,
    );
  if (mismatches.length > 0) {
    throw new GateError(
      "runner fingerprint differs from the recorded baseline:\n" +
        mismatches.join("\n"),
    );
  }
}

function parseBenchmarkOutput(output) {
  const lines = output.split(/\r?\n/);
  const values = {};
  for (let index = 0; index < lines.length; index += 1) {
    const matched = BENCHMARK_LINE.exec(lines[index]);
    if (matched === null) {
      continue;
    }
    const name = matched[1];
    let mean = null;
    for (
      let followingIndex = index + 1;
      followingIndex < Math.min(index + 5, lines.length);
      followingIndex += 1
    ) {
      const timing = MEAN_LINE.exec(lines[followingIndex]);
      if (timing !== null) {
        mean =
          Number.parseFloat(timing[1]) * TIME_FACTORS[timing[2]];
        break;
      }
    }
    if (mean === null) {
      throw new GateError(
        `benchmark output omitted the mean for ${reprString(name)}`,
      );
    }
    values[name] = mean;
  }
  const expected = new Set(Object.keys(BENCHMARKS));
  const actual = new Set(Object.keys(values));
  const missing = [...expected]
    .filter((name) => !actual.has(name))
    .sort();
  const extra = [...actual]
    .filter((name) => !expected.has(name))
    .sort();
  if (missing.length > 0 || extra.length > 0) {
    const details = [];
    if (missing.length > 0) {
      details.push(`missing benchmarks: ${missing.join(", ")}`);
    }
    if (extra.length > 0) {
      details.push(`unexpected benchmarks: ${extra.join(", ")}`);
    }
    throw new GateError(details.join("; "));
  }
  return values;
}

function metricValues(seconds) {
  const result = {};
  for (const [name, duration] of Object.entries(seconds)) {
    const definition = BENCHMARKS[name];
    result[name] =
      definition.kind === "latency"
        ? duration
        : definition.workload_bytes / duration;
  }
  return result;
}

async function benchmarkOnce(tree) {
  const environment = { ...process.env, LC_ALL: "C.UTF-8" };
  const started = performance.now();
  const result = await run(BENCHMARK_COMMAND, {
    cwd: tree,
    environment,
  });
  const elapsed = (performance.now() - started) / 1000;
  const seconds = parseBenchmarkOutput(result.stdout);
  return {
    elapsed_seconds: elapsed,
    seconds_per_operation: seconds,
    metrics: metricValues(seconds),
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

async function warm(tree, count, label) {
  for (let index = 0; index < count; index += 1) {
    console.log(`warmup ${label} ${index + 1}/${count}`);
    await benchmarkOnce(tree);
  }
}

async function sample(tree, count, label) {
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    console.log(`sample ${label} ${index + 1}/${count}`);
    samples.push(await benchmarkOnce(tree));
  }
  return samples;
}

function validateCounts(warmups, samples) {
  if (warmups < MIN_WARMUPS) {
    throw new GateError(`at least ${MIN_WARMUPS} warmups are required`);
  }
  if (samples < MIN_SAMPLES) {
    throw new GateError(`at least ${MIN_SAMPLES} samples are required`);
  }
}

function median(values) {
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 1
    ? ordered[middle]
    : (ordered[middle - 1] + ordered[middle]) / 2;
}

function aggregate(samples) {
  const result = {};
  for (const [name, definition] of Object.entries(BENCHMARKS)) {
    const values = samples.map((entry) => entry.metrics[name]);
    result[name] = {
      kind: String(definition.kind),
      median: median(values),
      minimum: Math.min(...values),
      maximum: Math.max(...values),
    };
  }
  return result;
}

function manifest({ revision, dirty, tree, warmups, samples }) {
  return {
    format_version: FORMAT_VERSION,
    baseline_commit: revision,
    dirty,
    benchmark_command: BENCHMARK_COMMAND,
    benchmark_source: BENCHMARK_SOURCE,
    benchmark_source_sha256: fileSha256(
      join(tree, BENCHMARK_SOURCE),
    ),
    warmups,
    sample_count: samples.length,
    threshold: THRESHOLD,
    runner: runnerFingerprint(),
    definitions: BENCHMARKS,
    aggregate: aggregate(samples),
    raw_results: samples,
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

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${jsonDumps(value)}\n`, "utf8");
  renameSync(temporary, path);
}

async function commandRecord(arguments_) {
  const repo = resolve(arguments_.repo);
  validateCounts(arguments_.warmups, arguments_.samples);
  const { revision, dirty } = await committedRevision(repo, {
    allowDirty: false,
  });
  const source = join(repo, BENCHMARK_SOURCE);
  if (!isFile(source)) {
    throw new GateError(`benchmark source is missing: ${source}`);
  }
  await warm(repo, arguments_.warmups, "baseline");
  const samples = await sample(
    repo,
    arguments_.samples,
    "baseline",
  );
  const output = resolve(arguments_.output);
  writeJson(
    output,
    manifest({
      revision,
      dirty,
      tree: repo,
      warmups: arguments_.warmups,
      samples,
    }),
  );
  console.log(`recorded baseline ${revision} in ${output}`);
  return 0;
}

async function createWorktree(repo, revision, directory) {
  const target = join(directory, "baseline");
  await run(["git", "worktree", "add", "--detach", target, revision], {
    cwd: repo,
  });
  return target;
}

async function removeWorktree(repo, tree) {
  const result = await run(
    ["git", "worktree", "remove", "--force", tree],
    { cwd: repo, check: false },
  );
  if (result.returncode !== 0) {
    console.error(
      "warning: failed to remove temporary baseline worktree: " +
        (result.stderr.trim() || result.stdout.trim()),
    );
  }
}

function compareAggregate(baselineSamples, candidateSamples) {
  const rows = [];
  let failed = false;
  for (const [name, definition] of Object.entries(BENCHMARKS)) {
    const baseline = median(
      baselineSamples.map((entry) => entry.metrics[name]),
    );
    const candidate = median(
      candidateSamples.map((entry) => entry.metrics[name]),
    );
    const kind = definition.kind;
    const ratio = candidate / baseline;
    const regression =
      kind === "latency"
        ? ratio > 1 + THRESHOLD
        : ratio < 1 - THRESHOLD;
    const change = ratio - 1;
    failed ||= regression;
    rows.push({
      name,
      kind,
      baseline_median: baseline,
      candidate_median: candidate,
      candidate_over_baseline: ratio,
      change,
      regression,
    });
  }
  return { rows, failed };
}

function formatGeneral(value, precision = 6) {
  if (value === 0) {
    return "0";
  }
  const exponent = Math.floor(Math.log10(Math.abs(value)));
  if (exponent < -4 || exponent >= precision) {
    const [mantissa, exponentText] = value
      .toExponential(precision - 1)
      .split("e");
    const trimmed = mantissa
      .replace(/(\.\d*?[1-9])0+$/, "$1")
      .replace(/\.0+$/, "");
    const exponentNumber = Number.parseInt(exponentText, 10);
    const sign = exponentNumber >= 0 ? "+" : "-";
    return `${trimmed}e${sign}${Math.abs(exponentNumber)
      .toString()
      .padStart(2, "0")}`;
  }
  const decimals = Math.max(0, precision - exponent - 1);
  return value
    .toFixed(decimals)
    .replace(/(\.\d*?[1-9])0+$/, "$1")
    .replace(/\.0+$/, "");
}

function printComparison(rows) {
  for (const row of rows) {
    const unit = row.kind === "latency" ? "s/op" : "bytes/s";
    const state = row.regression ? "FAIL" : "PASS";
    const percentage = `${row.change >= 0 ? "+" : ""}${(
      row.change * 100
    ).toFixed(1)}%`;
    console.log(
      `${state} ${row.name}: ` +
        `${formatGeneral(row.baseline_median)} → ` +
        `${formatGeneral(row.candidate_median)} ${unit} ` +
        `(${percentage})`,
    );
  }
}

async function commandCompare(arguments_) {
  const repo = resolve(arguments_.repo);
  const candidate = resolve(arguments_.candidate);
  validateCounts(arguments_.warmups, arguments_.samples);
  const baselineManifest = JSON.parse(
    readFileSync(resolve(arguments_.baseline), "utf8"),
  );
  if (baselineManifest.format_version !== FORMAT_VERSION) {
    throw new GateError("unsupported baseline manifest format");
  }
  if (
    !isDeepStrictEqual(
      baselineManifest.benchmark_command,
      BENCHMARK_COMMAND,
    )
  ) {
    throw new GateError(
      "baseline benchmark command differs from this gate",
    );
  }
  if (
    !isDeepStrictEqual(baselineManifest.definitions, BENCHMARKS)
  ) {
    throw new GateError(
      "baseline benchmark definitions differ from this gate",
    );
  }
  const {
    revision: candidateRevision,
    dirty: candidateDirty,
  } = await committedRevision(candidate, {
    allowDirty: arguments_.allowDirty,
  });
  const candidateSourceHash = fileSha256(
    join(candidate, BENCHMARK_SOURCE),
  );
  const expectedSourceHash =
    baselineManifest.benchmark_source_sha256;
  if (candidateSourceHash !== expectedSourceHash) {
    throw new GateError(
      "benchmark fixture/workload changed; record a new reviewed baseline",
    );
  }
  checkRunner(baselineManifest.runner, runnerFingerprint());
  const baselineRevision = baselineManifest.baseline_commit;
  const temporary = mkdtempSync(
    join(tmpdir(), "rtc-mbt-bench-gate-"),
  );
  let baselineTree = null;
  try {
    baselineTree = await createWorktree(
      repo,
      baselineRevision,
      temporary,
    );
    if (
      fileSha256(join(baselineTree, BENCHMARK_SOURCE)) !==
      expectedSourceHash
    ) {
      throw new GateError(
        "recorded baseline commit does not contain the recorded workload",
      );
    }
    for (let index = 0; index < arguments_.warmups; index += 1) {
      const order =
        index % 2 === 0
          ? [
              ["baseline", baselineTree],
              ["candidate", candidate],
            ]
          : [
              ["candidate", candidate],
              ["baseline", baselineTree],
            ];
      for (const [label, tree] of order) {
        console.log(
          `warmup ${label} ${index + 1}/${arguments_.warmups}`,
        );
        await benchmarkOnce(tree);
      }
    }
    const baselineSamples = [];
    const candidateSamples = [];
    for (let index = 0; index < arguments_.samples; index += 1) {
      const order =
        index % 2 === 0
          ? [
              ["baseline", baselineTree, baselineSamples],
              ["candidate", candidate, candidateSamples],
            ]
          : [
              ["candidate", candidate, candidateSamples],
              ["baseline", baselineTree, baselineSamples],
            ];
      for (const [label, tree, destination] of order) {
        console.log(
          `interleaved sample ${index + 1}/${arguments_.samples}: ` +
            label,
        );
        destination.push(await benchmarkOnce(tree));
      }
    }
    const { rows, failed } = compareAggregate(
      baselineSamples,
      candidateSamples,
    );
    const report = {
      format_version: FORMAT_VERSION,
      baseline_commit: baselineRevision,
      candidate_commit: candidateRevision,
      candidate_dirty: candidateDirty,
      benchmark_source_sha256: expectedSourceHash,
      warmups: arguments_.warmups,
      sample_count: arguments_.samples,
      threshold: THRESHOLD,
      runner: runnerFingerprint(),
      comparison: rows,
      baseline_raw_results: baselineSamples,
      candidate_raw_results: candidateSamples,
      passed: !failed,
    };
    const output = resolve(arguments_.output);
    writeJson(output, report);
    printComparison(rows);
    console.log(`raw comparison written to ${output}`);
    return failed ? 1 : 0;
  } finally {
    if (baselineTree !== null) {
      await removeWorktree(repo, baselineTree);
    }
    rmSync(temporary, { recursive: true, force: true });
  }
}

function commandSelfTest() {
  const fixture = Object.keys(BENCHMARKS)
    .flatMap((name) => [
      `[moonbit-community/rtc] bench rtc_bench_test.mbt:1 ("${name}") ok`,
      "time (mean ± σ)         range (min … max)",
      "   2.50 µs ±  10.00 ns     2.40 µs … 2.60 µs in 10 × 10 runs",
    ])
    .join("\n");
  const parsed = parseBenchmarkOutput(fixture);
  if (
    Object.values(parsed).some(
      (value) => Math.abs(value - 2.5e-6) > 1.0e-15,
    )
  ) {
    throw new GateError("benchmark parser self-test failed");
  }
  const baseline = [
    {
      metrics: Object.fromEntries(
        Object.keys(BENCHMARKS).map((name) => [name, 100]),
      ),
    },
  ];
  const candidateMetrics = Object.fromEntries(
    Object.entries(BENCHMARKS).map(([name, definition]) => [
      name,
      definition.kind === "latency" ? 121 : 79,
    ]),
  );
  const { rows, failed } = compareAggregate(baseline, [
    { metrics: candidateMetrics },
  ]);
  if (!failed || !rows.every((row) => row.regression)) {
    throw new GateError("regression threshold self-test failed");
  }
  const fingerprintFields = new Set(
    Object.keys(runnerFingerprint()),
  );
  if (
    !["machine", "cpu_model", "runner_id"].every((field) =>
      fingerprintFields.has(field),
    ) ||
    fingerprintFields.size !== 3
  ) {
    throw new GateError("runner fingerprint fields self-test failed");
  }
  for (const [field, value] of [
    ["machine", "aarch64"],
    ["cpu_model", "different CPU"],
    ["runner_id", "runner-b"],
  ]) {
    const candidateRunner = {
      machine: "x86_64",
      cpu_model: "test CPU",
      runner_id: "runner-a",
      [field]: value,
    };
    let raised = false;
    try {
      checkRunner(
        {
          machine: "x86_64",
          cpu_model: "test CPU",
          runner_id: "runner-a",
        },
        candidateRunner,
      );
    } catch (error) {
      if (!(error instanceof GateError)) {
        throw error;
      }
      raised = true;
    }
    if (!raised) {
      throw new GateError(
        `runner ${field} mismatch self-test failed`,
      );
    }
  }
  console.log("bench-gate self-test: PASS");
  return 0;
}

function printGlobalHelp() {
  console.log(`usage: bench-gate.mjs {record,compare,self-test} ...

Record and compare the rtc.mbt native benchmark baseline.

commands:
  record              record a committed baseline
  compare             compare a candidate with the recorded baseline commit
  self-test           test output parsing and threshold behavior without
                      benchmarking`);
}

function printCommandHelp(command) {
  if (command === "record") {
    console.log(`usage: bench-gate.mjs record [--repo REPO] [--output OUTPUT]
                             [--warmups WARMUPS] [--samples SAMPLES]

options:
  --repo REPO
  --output OUTPUT
  --warmups WARMUPS
  --samples SAMPLES`);
    return;
  }
  if (command === "compare") {
    console.log(`usage: bench-gate.mjs compare [--repo REPO]
                              [--candidate CANDIDATE]
                              [--baseline BASELINE] [--output OUTPUT]
                              [--warmups WARMUPS] [--samples SAMPLES]
                              [--allow-dirty]

options:
  --repo REPO          Git repository used to create the baseline worktree
  --candidate CANDIDATE
  --baseline BASELINE
  --output OUTPUT
  --warmups WARMUPS
  --samples SAMPLES
  --allow-dirty        allow an uncommitted candidate; the baseline must
                       remain committed`);
    return;
  }
  console.log(`usage: bench-gate.mjs self-test`);
}

function optionValue(arguments_, index, name) {
  const argument = arguments_[index];
  const prefix = `${name}=`;
  if (argument.startsWith(prefix)) {
    return { value: argument.slice(prefix.length), consumed: 0 };
  }
  if (argument === name) {
    if (index + 1 >= arguments_.length) {
      throw new GateError(`argument ${name}: expected one argument`);
    }
    return { value: arguments_[index + 1], consumed: 1 };
  }
  return null;
}

function integerOption(value, name) {
  if (!/^-?\d+$/.test(value)) {
    throw new GateError(`argument ${name}: invalid int value: ${value}`);
  }
  return Number.parseInt(value, 10);
}

function parseOptions(command, arguments_) {
  const parsed =
    command === "record"
      ? {
          command,
          repo: REPOSITORY_ROOT,
          output: "benchmarks/baseline.json",
          warmups: MIN_WARMUPS,
          samples: MIN_SAMPLES,
          help: false,
        }
      : {
          command,
          repo: REPOSITORY_ROOT,
          candidate: process.cwd(),
          baseline: "benchmarks/baseline.json",
          output: "benchmarks/last-comparison.json",
          warmups: MIN_WARMUPS,
          samples: MIN_SAMPLES,
          allowDirty: false,
          help: false,
        };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "-h" || argument === "--help") {
      parsed.help = true;
      continue;
    }
    const optionNames =
      command === "record"
        ? ["--repo", "--output", "--warmups", "--samples"]
        : [
            "--repo",
            "--candidate",
            "--baseline",
            "--output",
            "--warmups",
            "--samples",
          ];
    let matched = false;
    for (const name of optionNames) {
      const option = optionValue(arguments_, index, name);
      if (option === null) {
        continue;
      }
      const key = {
        "--repo": "repo",
        "--candidate": "candidate",
        "--baseline": "baseline",
        "--output": "output",
        "--warmups": "warmups",
        "--samples": "samples",
      }[name];
      parsed[key] =
        name === "--warmups" || name === "--samples"
          ? integerOption(option.value, name)
          : option.value;
      index += option.consumed;
      matched = true;
      break;
    }
    if (matched) {
      continue;
    }
    if (command === "compare" && argument === "--allow-dirty") {
      parsed.allowDirty = true;
      continue;
    }
    throw new GateError(`unrecognized argument: ${argument}`);
  }
  return parsed;
}

function parseArguments(arguments_) {
  if (arguments_.length === 0) {
    throw new GateError(
      "a command is required: record, compare, or self-test",
    );
  }
  if (arguments_[0] === "-h" || arguments_[0] === "--help") {
    return { help: true, command: null };
  }
  const [command, ...remaining] = arguments_;
  if (!["record", "compare", "self-test"].includes(command)) {
    throw new GateError(`unknown command: ${command}`);
  }
  if (command === "self-test") {
    if (
      remaining.length === 1 &&
      (remaining[0] === "-h" || remaining[0] === "--help")
    ) {
      return { command, help: true };
    }
    if (remaining.length > 0) {
      throw new GateError(
        `unrecognized argument: ${remaining[0]}`,
      );
    }
    return { command, help: false };
  }
  return parseOptions(command, remaining);
}

function handleSignal(signal) {
  interruptedSignal ??= signal;
  if (
    activeChild !== null &&
    activeChild.exitCode === null &&
    activeChild.signalCode === null
  ) {
    activeChild.kill(signal);
  }
}

function interruptedExitCode() {
  return 128 + (osConstants.signals[interruptedSignal] ?? 0);
}

async function main(arguments_) {
  const parsed = parseArguments(arguments_);
  if (parsed.help) {
    if (parsed.command === null) {
      printGlobalHelp();
    } else {
      printCommandHelp(parsed.command);
    }
    return 0;
  }
  if (parsed.command === "record") {
    return await commandRecord(parsed);
  }
  if (parsed.command === "compare") {
    return await commandCompare(parsed);
  }
  return commandSelfTest();
}

const onSigint = () => handleSignal("SIGINT");
const onSigterm = () => handleSignal("SIGTERM");
process.on("SIGINT", onSigint);
process.on("SIGTERM", onSigterm);
try {
  const status = await main(process.argv.slice(2));
  process.exitCode =
    interruptedSignal === null ? status : interruptedExitCode();
} catch (error) {
  if (interruptedSignal !== null) {
    console.error(`bench-gate: interrupted by ${interruptedSignal}`);
    process.exitCode = interruptedExitCode();
  } else {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`bench-gate: ${message}`);
    process.exitCode = 2;
  }
} finally {
  process.off("SIGINT", onSigint);
  process.off("SIGTERM", onSigterm);
}
