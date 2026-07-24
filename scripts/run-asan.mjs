#!/usr/bin/env node

/**
 * Run every native rtc.mbt test under AddressSanitizer.
 *
 * The runner temporarily injects ASan flags into every repository package that
 * contains tests and every package that declares native C stubs. It constructs
 * an isolated view of the installed MoonBit toolchain and replaces only that
 * view's mimalloc object with an empty object so ASan can observe allocations.
 * All modified repository files are restored in a finally block, including on
 * test failure or interruption.
 */

import {
  accessSync,
  chmodSync,
  constants as fsConstants,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { constants as osConstants, tmpdir } from "node:os";
import {
  delimiter,
  dirname,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ASAN_FLAGS = "-g -fsanitize=address -fno-omit-frame-pointer";
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIRECTORY = dirname(SCRIPT_PATH);

class RunnerError extends Error {}

let activeChild = null;
let interruptedSignal = null;

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function findExecutable(name) {
  if (name.includes(sep)) {
    try {
      accessSync(name, fsConstants.X_OK);
      return resolve(name);
    } catch {
      return null;
    }
  }
  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (!directory) {
      continue;
    }
    const candidate = join(directory, name);
    try {
      accessSync(candidate, fsConstants.X_OK);
      if (isFile(candidate)) {
        return candidate;
      }
    } catch {
      // Continue searching PATH.
    }
  }
  return null;
}

function findMoonHome() {
  const moon = findExecutable("moon");
  if (moon === null) {
    throw new RunnerError("moon is not on PATH");
  }
  const home = dirname(dirname(realpathSync(moon)));
  const runtime = join(home, "lib", "libmoonbitrun.o");
  if (!isFile(runtime)) {
    throw new RunnerError(`MoonBit runtime object not found: ${runtime}`);
  }
  return home;
}

function findOptionsClose(text) {
  const marker = "options(";
  const start = text.indexOf(marker);
  if (start < 0) {
    return null;
  }
  let depth = 1;
  let index = start + marker.length;
  let quote = null;
  let escaped = false;
  while (index < text.length) {
    const character = text[index];
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
    index += 1;
  }
  throw new RunnerError("unterminated options(...) block");
}

function linkEntry({ generated, stub }) {
  const fields = [];
  if (generated) {
    fields.push(`      "cc-flags": "${ASAN_FLAGS}",`);
  }
  if (stub) {
    fields.push(`      "stub-cc-flags": "${ASAN_FLAGS}",`);
  }
  return [
    "  link: {",
    '    "native": {',
    ...fields,
    "    },",
    "  },",
  ].join("\n");
}

function patchPackage(text, { generated, stub }) {
  if (!generated && !stub) {
    return text;
  }
  if (text.includes("link:") || text.includes('"link":')) {
    throw new RunnerError(
      "ASan runner cannot safely merge an existing link block; " +
        "extend scripts/run-asan.mjs before adding permanent link flags",
    );
  }
  const entry = linkEntry({ generated, stub });
  const close = findOptionsClose(text);
  if (close === null) {
    const separator = text.endsWith("\n") ? "" : "\n";
    return `${text}${separator}\noptions(\n${entry}\n)\n`;
  }
  const prefix = text.slice(0, close);
  const suffix = text.slice(close);
  const stripped = prefix.trimEnd();
  const insertion =
    stripped.endsWith("(") || stripped.endsWith(",")
      ? `\n${entry}\n`
      : `,\n${entry}\n`;
  return prefix + insertion + suffix;
}

function packageRoles(packagePath) {
  const text = readFileSync(packagePath, "utf8");
  const directory = dirname(packagePath);
  const generated =
    readdirSync(directory, { withFileTypes: true }).some((entry) =>
      entry.name.endsWith("_test.mbt"),
    ) ||
    text.includes('"is-main": true') ||
    text.includes("is_main: true") ||
    /pkgtype\s*\(\s*kind\s*:\s*"executable"\s*\)/.test(text);
  const stub = text.includes('"native-stub"');
  return { generated, stub };
}

function collectPackageFiles(directory, result) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === "_build" || entry.name === ".mooncakes") {
      continue;
    }
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      collectPackageFiles(path, result);
    } else if (entry.isFile() && entry.name === "moon.pkg") {
      result.push(path);
    }
  }
}

function selectPackages(root) {
  const packageFiles = [];
  collectPackageFiles(root, packageFiles);
  packageFiles.sort();
  const selected = [];
  for (const packagePath of packageFiles) {
    const roles = packageRoles(packagePath);
    if (roles.generated || roles.stub) {
      selected.push({ path: packagePath, ...roles });
    }
  }
  return selected;
}

function copyWithMode(source, destination) {
  copyFileSync(source, destination);
  chmodSync(destination, statSync(source).mode);
}

function linkTo(source, destination) {
  const type = statSync(source).isDirectory() ? "dir" : "file";
  symlinkSync(source, destination, type);
}

function isolatedToolchain(temporary) {
  const original = findMoonHome();
  const isolated = join(temporary, "moon");
  mkdirSync(isolated);
  for (const entry of readdirSync(original, { withFileTypes: true })) {
    const source = join(original, entry.name);
    const destination = join(isolated, entry.name);
    if (entry.name !== "bin" && entry.name !== "lib") {
      linkTo(source, destination);
      continue;
    }
    mkdirSync(destination);
    for (const child of readdirSync(source, { withFileTypes: true })) {
      const childSource = join(source, child.name);
      const childDestination = join(destination, child.name);
      if (entry.name === "bin" && child.name === "moon") {
        copyWithMode(childSource, childDestination);
      } else if (
        entry.name === "lib" &&
        child.name === "libmoonbitrun.o"
      ) {
        copyWithMode(childSource, childDestination);
      } else {
        linkTo(childSource, childDestination);
      }
    }
  }
  const moon = join(isolated, "bin", "moon");
  const runtime = join(isolated, "lib", "libmoonbitrun.o");
  if (!isFile(moon) || !isFile(runtime)) {
    throw new RunnerError(
      "failed to construct the isolated MoonBit toolchain",
    );
  }
  return { moon, runtime };
}

function commandDetail(result) {
  return result.stderr.trim() || result.stdout.trim();
}

function runCommand(
  command,
  arguments_,
  { cwd = undefined, env = undefined, inherit = false } = {},
) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, {
      cwd,
      env,
      stdio: inherit ? "inherit" : ["ignore", "pipe", "pipe"],
    });
    activeChild = child;
    let stdout = "";
    let stderr = "";
    let settled = false;
    if (!inherit) {
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
    }
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
      finish(() => rejectPromise(new RunnerError(error.message)));
    });
    child.once("close", (status, signal) => {
      finish(() =>
        resolvePromise({
          status,
          signal,
          stdout,
          stderr,
        }),
      );
    });
  });
}

async function runChecked(command, arguments_) {
  const result = await runCommand(command, arguments_);
  if (result.status !== 0) {
    const detail = commandDetail(result);
    throw new RunnerError(
      `command failed (${result.status ?? result.signal}): ` +
        [command, ...arguments_].join(" ") +
        (detail ? `\n${detail}` : ""),
    );
  }
}

async function disableMimalloc(compiler, runtime, temporary) {
  const source = join(temporary, "empty.c");
  const replacement = join(temporary, "libmoonbitrun.o");
  writeFileSync(source, "");
  await runChecked(compiler, ["-c", source, "-o", replacement]);
  copyWithMode(replacement, runtime);
}

function printHelp() {
  console.log(`usage: run-asan.mjs [--repo-root REPO_ROOT] [--no-disable-mimalloc]
                    [--package PACKAGE]

options:
  -h, --help            show this help message and exit
  --repo-root REPO_ROOT
  --no-disable-mimalloc
                        Keep MoonBit's allocator; useful only for runner
                        diagnostics.
  --package PACKAGE     Limit moon test to one package while diagnosing a
                        sanitizer failure.`);
}

function optionValue(arguments_, index, name) {
  const argument = arguments_[index];
  const prefix = `${name}=`;
  if (argument.startsWith(prefix)) {
    return { value: argument.slice(prefix.length), consumed: 0 };
  }
  if (argument === name) {
    if (index + 1 >= arguments_.length) {
      throw new RunnerError(`argument ${name}: expected one argument`);
    }
    return { value: arguments_[index + 1], consumed: 1 };
  }
  return null;
}

function parseArguments(arguments_) {
  const parsed = {
    repoRoot: resolve(SCRIPT_DIRECTORY, ".."),
    noDisableMimalloc: false,
    package: null,
    help: false,
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "-h" || argument === "--help") {
      parsed.help = true;
      continue;
    }
    const repoRoot = optionValue(arguments_, index, "--repo-root");
    if (repoRoot !== null) {
      parsed.repoRoot = resolve(repoRoot.value);
      index += repoRoot.consumed;
      continue;
    }
    const packageOption = optionValue(arguments_, index, "--package");
    if (packageOption !== null) {
      parsed.package = packageOption.value;
      index += packageOption.consumed;
      continue;
    }
    if (argument === "--no-disable-mimalloc") {
      parsed.noDisableMimalloc = true;
      continue;
    }
    throw new RunnerError(`unrecognized argument: ${argument}`);
  }
  return parsed;
}

async function runTests(command, arguments_, options) {
  const result = await runCommand(command, arguments_, {
    cwd: options.cwd,
    env: options.env,
    inherit: true,
  });
  if (result.status !== null) {
    return result.status;
  }
  const signalNumber = result.signal
    ? (osConstants.signals[result.signal] ?? 0)
    : 0;
  return signalNumber > 0 ? 128 + signalNumber : 1;
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

async function main(arguments_) {
  const parsed = parseArguments(arguments_);
  if (parsed.help) {
    printHelp();
    return 0;
  }
  const root = resolve(parsed.repoRoot);
  if (
    !isFile(join(root, "moon.mod")) &&
    !isFile(join(root, "moon.mod.json"))
  ) {
    throw new RunnerError(`not a MoonBit module: ${root}`);
  }
  if (process.platform !== "linux") {
    throw new RunnerError(
      "the initial rtc.mbt ASan runner supports Linux only",
    );
  }
  const compiler = findExecutable("cc") ?? "gcc";
  const packages = selectPackages(root);
  if (packages.length === 0) {
    throw new RunnerError("no test or native-stub packages found");
  }

  const snapshots = new Map(
    packages.map((package_) => [
      package_.path,
      readFileSync(package_.path, "utf8"),
    ]),
  );
  const environment = {
    ...process.env,
    MOONBIT_NEW_NATIVE: "0",
    ASAN_OPTIONS:
      "detect_leaks=1:fast_unwind_on_malloc=0:halt_on_error=1",
  };
  try {
    for (const package_ of packages) {
      writeFileSync(
        package_.path,
        patchPackage(snapshots.get(package_.path), package_),
        "utf8",
      );
      const roles = [
        package_.generated ? "test-entry" : null,
        package_.stub ? "native-stub" : null,
      ]
        .filter((role) => role !== null)
        .join("/");
      console.log(
        `ASan flags: ${relative(root, package_.path)} (${roles})`,
      );
    }

    const temporary = mkdtempSync(join(tmpdir(), "rtc-mbt-asan-"));
    try {
      let moon = findExecutable("moon") ?? "moon";
      if (!parsed.noDisableMimalloc) {
        const isolated = isolatedToolchain(temporary);
        moon = isolated.moon;
        await disableMimalloc(
          compiler,
          isolated.runtime,
          temporary,
        );
        console.log(
          `mimalloc disabled in isolated toolchain: ${isolated.runtime}`,
        );
      }
      const command = ["test"];
      if (parsed.package !== null) {
        command.push(parsed.package);
      }
      command.push("--target", "native", "--no-parallelize", "-v");
      return await runTests(moon, command, {
        cwd: root,
        env: environment,
      });
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  } finally {
    for (const [packagePath, original] of snapshots) {
      writeFileSync(packagePath, original, "utf8");
    }
    console.log("restored package files");
  }
}

const onSigint = () => handleSignal("SIGINT");
const onSigterm = () => handleSignal("SIGTERM");
process.on("SIGINT", onSigint);
process.on("SIGTERM", onSigterm);
try {
  const status = await main(process.argv.slice(2));
  process.exitCode =
    interruptedSignal === null
      ? status
      : 128 + (osConstants.signals[interruptedSignal] ?? 0);
} catch (error) {
  if (interruptedSignal !== null) {
    console.error(`interrupted by ${interruptedSignal}`);
    process.exitCode =
      128 + (osConstants.signals[interruptedSignal] ?? 0);
  } else {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`error: ${message}`);
    process.exitCode = 2;
  }
} finally {
  process.off("SIGINT", onSigint);
  process.off("SIGTERM", onSigterm);
}
