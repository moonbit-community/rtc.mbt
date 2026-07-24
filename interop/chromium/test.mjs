import assert from "node:assert/strict";
import dgram from "node:dgram";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { chromium } from "playwright";

const interopDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(interopDirectory, "../..");
const keepArtifacts = process.env.KEEP_INTEROP_ARTIFACTS === "1";
const timeoutMilliseconds = 30_000;

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForFile(file, description) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    try {
      await access(file);
      return await readFile(file, "utf8");
    } catch {
      await delay(10);
    }
  }
  throw new Error(`timed out waiting for ${description}: ${file}`);
}

async function reserveUdpPort() {
  const socket = dgram.createSocket("udp4");
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", resolve);
  });
  const address = socket.address();
  await new Promise((resolve) => socket.close(resolve));
  return address.port;
}

function moonPeer(arguments_, log) {
  const child = spawn(
    "moon",
    [
      "run",
      "interop/moon-peer",
      "--target",
      "native",
      "--",
      ...arguments_,
    ],
    {
      cwd: repositoryRoot,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  child.stdout.on("data", (chunk) => {
    log.push(chunk.toString());
    process.stdout.write(chunk);
  });
  child.stderr.on("data", (chunk) => {
    log.push(chunk.toString());
    process.stderr.write(chunk);
  });
  return child;
}

async function childExit(child) {
  return await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolve();
      } else {
        reject(
          new Error(
            `MoonBit peer exited with ${
              signal === null ? `status ${code}` : `signal ${signal}`
            }`,
          ),
        );
      }
    });
  });
}

async function browserRevision() {
  const expected = JSON.parse(
    await readFile(path.join(interopDirectory, "browser-revision.json"), "utf8"),
  );
  const manifest = JSON.parse(
    await readFile(
      path.join(
        interopDirectory,
        "node_modules",
        "playwright-core",
        "browsers.json",
      ),
      "utf8",
    ),
  );
  const chromiumEntry = manifest.browsers.find(
    (entry) => entry.name === "chromium",
  );
  assert.ok(chromiumEntry, "Playwright manifest omitted Chromium");
  assert.equal(chromiumEntry.revision, expected.revision);
  assert.equal(chromiumEntry.browserVersion, expected.browserVersion);
  return expected;
}

async function initializeAnswerer(page, offerSdp, mode) {
  return await page.evaluate(
    async ({ offerSdp: remoteSdp, mode: reliabilityMode, timeout }) => {
      const withTimeout = (promise, description) =>
        Promise.race([
          promise,
          new Promise((_, reject) => {
            setTimeout(
              () => reject(new Error(`timed out waiting for ${description}`)),
              timeout,
            );
          }),
        ]);
      const binaryFixture = () =>
        Uint8Array.from(
          { length: 2500 },
          (_, index) => (index * 31 + 7) % 251,
        );
      const equalBytes = (left, right) =>
        left.length === right.length &&
        left.every((value, index) => value === right[index]);
      const peer = new RTCPeerConnection({ iceServers: [] });
      for (const eventName of [
        "connectionstatechange",
        "iceconnectionstatechange",
        "icegatheringstatechange",
        "signalingstatechange",
      ]) {
        peer.addEventListener(eventName, () => {
          console.log(
            `${eventName}: connection=${peer.connectionState} ` +
              `ice=${peer.iceConnectionState} ` +
              `gathering=${peer.iceGatheringState} ` +
              `signaling=${peer.signalingState}`,
          );
        });
      }
      let resolveDone;
      let rejectDone;
      let resolveClosed;
      const dataDone = new Promise((resolve, reject) => {
        resolveDone = resolve;
        rejectDone = reject;
      });
      const closed = new Promise((resolve) => {
        resolveClosed = resolve;
      });
      peer.ondatachannel = ({ channel }) => {
        try {
          if (channel.label !== "interop") {
            throw new Error(`unexpected DataChannel label ${channel.label}`);
          }
          if (
            reliabilityMode === "reliable" ||
            reliabilityMode === "media"
          ) {
            assertChannel(
              channel.ordered &&
                channel.maxRetransmits === null &&
                channel.maxPacketLifeTime === null,
              "reliable DataChannel parameters did not round-trip",
            );
          } else {
            assertChannel(
              !channel.ordered &&
                channel.maxRetransmits === 2 &&
                channel.maxPacketLifeTime === null,
              "partial DataChannel parameters did not round-trip",
            );
          }
          channel.binaryType = "arraybuffer";
          let sawText = false;
          let sawBinary = false;
          channel.onmessage = ({ data }) => {
            try {
              if (typeof data === "string") {
                assertChannel(
                  data === "moonbit-rust-text",
                  `unexpected text payload ${data}`,
                );
                sawText = true;
                channel.send(data);
              } else {
                const received = new Uint8Array(data);
                assertChannel(
                  equalBytes(received, binaryFixture()),
                  "fragmented binary payload differs",
                );
                sawBinary = true;
                channel.send(received);
              }
              if (sawText && sawBinary) {
                resolveDone();
              }
            } catch (error) {
              rejectDone(error);
            }
          };
          channel.onclose = resolveClosed;
          channel.onerror = () =>
            rejectDone(new Error("Chromium DataChannel reported an error"));
        } catch (error) {
          rejectDone(error);
        }
      };
      const assertChannel = (condition, message) => {
        if (!condition) {
          throw new Error(message);
        }
      };
      await peer.setRemoteDescription({ type: "offer", sdp: remoteSdp });
      await peer.setLocalDescription(await peer.createAnswer());
      if (peer.iceGatheringState !== "complete") {
        await withTimeout(
          new Promise((resolve) => {
            peer.addEventListener(
              "icegatheringstatechange",
              () => {
                if (peer.iceGatheringState === "complete") {
                  resolve();
                }
              },
              { once: false },
            );
          }),
          "Chromium ICE gathering",
        );
      }
      const mediaDone =
        reliabilityMode === "media"
          ? (async () => {
              const deadline = performance.now() + timeout;
              while (performance.now() < deadline) {
                let sawAudio = false;
                let sawVideo = false;
                for (const report of (await peer.getStats()).values()) {
                  if (
                    report.type !== "inbound-rtp" ||
                    report.packetsReceived < 1
                  ) {
                    continue;
                  }
                  const kind = report.kind ?? report.mediaType;
                  sawAudio ||= kind === "audio";
                  sawVideo ||= kind === "video";
                }
                if (sawAudio && sawVideo) {
                  return;
                }
                await new Promise((resolve) => setTimeout(resolve, 10));
              }
              throw new Error(
                "timed out waiting for Chromium audio and video RTP",
              );
            })()
          : Promise.resolve();
      window.rtcInterop = {
        peer,
        done: Promise.all([dataDone, mediaDone]),
        closed,
      };
      return peer.localDescription.sdp;
    },
    {
      offerSdp,
      mode,
      timeout: timeoutMilliseconds,
    },
  );
}

async function initializeOfferer(page, mode) {
  return await page.evaluate(
    async ({ mode: reliabilityMode, timeout }) => {
      const withTimeout = (promise, description) =>
        Promise.race([
          promise,
          new Promise((_, reject) => {
            setTimeout(
              () => reject(new Error(`timed out waiting for ${description}`)),
              timeout,
            );
          }),
        ]);
      const binaryFixture = () =>
        Uint8Array.from(
          { length: 2500 },
          (_, index) => (index * 31 + 7) % 251,
        );
      const equalBytes = (left, right) =>
        left.length === right.length &&
        left.every((value, index) => value === right[index]);
      const peer = new RTCPeerConnection({ iceServers: [] });
      for (const eventName of [
        "connectionstatechange",
        "iceconnectionstatechange",
        "icegatheringstatechange",
        "signalingstatechange",
      ]) {
        peer.addEventListener(eventName, () => {
          console.log(
            `${eventName}: connection=${peer.connectionState} ` +
              `ice=${peer.iceConnectionState} ` +
              `gathering=${peer.iceGatheringState} ` +
              `signaling=${peer.signalingState}`,
          );
        });
      }
      const options =
        reliabilityMode === "partial"
          ? { ordered: false, maxRetransmits: 2 }
          : {};
      const channel = peer.createDataChannel("interop", options);
      let resources;
      if (reliabilityMode === "media") {
        const audioContext = new AudioContext();
        const oscillator = audioContext.createOscillator();
        const destination = audioContext.createMediaStreamDestination();
        oscillator.frequency.value = 440;
        oscillator.connect(destination);
        oscillator.start();

        const canvas = document.createElement("canvas");
        canvas.width = 32;
        canvas.height = 32;
        const context = canvas.getContext("2d");
        let frame = 0;
        const paint = () => {
          context.fillStyle = frame++ % 2 === 0 ? "#123456" : "#abcdef";
          context.fillRect(0, 0, canvas.width, canvas.height);
        };
        paint();
        const paintInterval = setInterval(paint, 50);
        const canvasStream = canvas.captureStream(20);
        const audioTrack = destination.stream.getAudioTracks()[0];
        const videoTrack = canvasStream.getVideoTracks()[0];
        const stream = new MediaStream([audioTrack, videoTrack]);
        peer.addTrack(audioTrack, stream);
        peer.addTrack(videoTrack, stream);
        resources = {
          audioContext,
          oscillator,
          paintInterval,
          tracks: [audioTrack, videoTrack],
        };
      }
      channel.binaryType = "arraybuffer";
      let resolveDone;
      let rejectDone;
      let resolveClosed;
      const done = new Promise((resolve, reject) => {
        resolveDone = resolve;
        rejectDone = reject;
      });
      const closed = new Promise((resolve) => {
        resolveClosed = resolve;
      });
      let sawText = false;
      let sawBinary = false;
      channel.onopen = () => {
        channel.send("rust-moonbit-text");
        channel.send(binaryFixture());
      };
      channel.onmessage = ({ data }) => {
        try {
          if (typeof data === "string") {
            if (data !== "rust-moonbit-text") {
              throw new Error(`unexpected text echo ${data}`);
            }
            sawText = true;
          } else {
            const received = new Uint8Array(data);
            if (!equalBytes(received, binaryFixture())) {
              throw new Error("fragmented binary echo differs");
            }
            sawBinary = true;
          }
          if (sawText && sawBinary) {
            resolveDone();
          }
        } catch (error) {
          rejectDone(error);
        }
      };
      channel.onclose = resolveClosed;
      channel.onerror = () =>
        rejectDone(new Error("Chromium DataChannel reported an error"));
      await peer.setLocalDescription(await peer.createOffer());
      if (peer.iceGatheringState !== "complete") {
        await withTimeout(
          new Promise((resolve) => {
            peer.addEventListener(
              "icegatheringstatechange",
              () => {
                if (peer.iceGatheringState === "complete") {
                  resolve();
                }
              },
              { once: false },
            );
          }),
          "Chromium ICE gathering",
        );
      }
      window.rtcInterop = { peer, channel, done, closed, resources };
      return peer.localDescription.sdp;
    },
    {
      mode,
      timeout: timeoutMilliseconds,
    },
  );
}

async function setAnswer(page, answerSdp) {
  await page.evaluate(
    async ({ answerSdp: remoteSdp }) => {
      await window.rtcInterop.peer.setRemoteDescription({
        type: "answer",
        sdp: remoteSdp,
      });
    },
    { answerSdp },
  );
}

async function awaitBrowserDone(page) {
  await page.evaluate(
    async (timeout) => {
      await Promise.race([
        window.rtcInterop.done,
        new Promise((_, reject) => {
          setTimeout(
            () =>
              reject(
                new Error("timed out waiting for Chromium DataChannel data"),
              ),
            timeout,
          );
        }),
      ]);
    },
    timeoutMilliseconds,
  );
}

async function awaitBrowserClose(page) {
  await page.evaluate(
    async (timeout) => {
      await Promise.race([
        window.rtcInterop.closed,
        new Promise((_, reject) => {
          setTimeout(
            () => reject(new Error("timed out waiting for channel close")),
            timeout,
          );
        }),
      ]);
      const resources = window.rtcInterop.resources;
      if (resources !== undefined) {
        clearInterval(resources.paintInterval);
        for (const track of resources.tracks) {
          track.stop();
        }
        resources.oscillator.stop();
        await resources.audioContext.close();
      }
      window.rtcInterop.peer.close();
    },
    timeoutMilliseconds,
  );
}

async function runCase(browser, fixtureDirectory, moonRole, mode) {
  const name = `moon-${moonRole}-${mode}`;
  const caseDirectory = path.join(fixtureDirectory, name);
  await mkdir(caseDirectory, { recursive: true });
  const offerPath = path.join(caseDirectory, "offer.sdp");
  const answerPath = path.join(caseDirectory, "answer.sdp");
  const moonResultPath = path.join(caseDirectory, "moon.ok");
  const browserResultPath = path.join(caseDirectory, "browser.ok");
  const log = [];
  const localPort = await reserveUdpPort();
  const child = moonPeer(
    [
      moonRole,
      mode,
      String(localPort),
      offerPath,
      answerPath,
      moonResultPath,
      browserResultPath,
    ],
    log,
  );
  const exit = childExit(child);
  exit.catch(() => {});
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on("console", (message) => {
    const line = `[chromium:${message.type()}] ${message.text()}\n`;
    log.push(line);
    process.stdout.write(line);
  });
  try {
    if (moonRole === "offer") {
      const offerSdp = await waitForFile(offerPath, "MoonBit offer");
      const answerSdp = await initializeAnswerer(page, offerSdp, mode);
      await writeFile(answerPath, answerSdp);
    } else {
      const offerSdp = await initializeOfferer(page, mode);
      await writeFile(offerPath, offerSdp);
      const answerSdp = await waitForFile(answerPath, "MoonBit answer");
      await setAnswer(page, answerSdp);
    }
    await awaitBrowserDone(page);
    await waitForFile(moonResultPath, "MoonBit completion marker");
    await writeFile(browserResultPath, "ok\n");
    await exit;
    await awaitBrowserClose(page);
    await writeFile(path.join(caseDirectory, "interop.log"), log.join(""));
    console.log(
      `MoonBit ${moonRole}er ↔ pinned Chromium ${
        moonRole === "offer" ? "answerer" : "offerer"
      } (${mode}): PASS`,
    );
  } catch (error) {
    const diagnostics = await page
      .evaluate(async () => {
        const state = window.rtcInterop;
        if (state === undefined) {
          return { initialized: false };
        }
        const selectedStats = [];
        for (const report of (await state.peer.getStats()).values()) {
          if (
            report.type === "candidate-pair" ||
            report.type === "transport" ||
            report.type === "local-candidate" ||
            report.type === "remote-candidate" ||
            report.type === "inbound-rtp" ||
            report.type === "outbound-rtp"
          ) {
            selectedStats.push(Object.fromEntries(Object.entries(report)));
          }
        }
        return {
          initialized: true,
          connectionState: state.peer.connectionState,
          iceConnectionState: state.peer.iceConnectionState,
          iceGatheringState: state.peer.iceGatheringState,
          signalingState: state.peer.signalingState,
          channelState: state.channel?.readyState ?? "remote-pending",
          stats: selectedStats,
        };
      })
      .catch((diagnosticError) => ({
        diagnosticError: String(diagnosticError),
      }));
    const diagnosticLine = `Chromium diagnostics: ${JSON.stringify(
      diagnostics,
    )}\n`;
    log.push(diagnosticLine);
    process.stderr.write(diagnosticLine);
    child.kill("SIGTERM");
    await exit.catch(() => {});
    await writeFile(path.join(caseDirectory, "interop.log"), log.join(""));
    throw error;
  } finally {
    await context.close();
  }
}

async function main() {
  const expectedRevision = await browserRevision();
  const fixtureDirectory = await mkdtemp(
    path.join(os.tmpdir(), "rtc-mbt-chromium-"),
  );
  const browser = await chromium.launch({
    headless: true,
    args: ["--disable-features=WebRtcHideLocalIpsWithMdns"],
  });
  try {
    assert.equal(browser.version(), expectedRevision.browserVersion);
    const cases = [];
    for (const mode of ["reliable", "partial", "media"]) {
      for (const role of ["offer", "answer"]) {
        cases.push({ role, mode });
      }
    }
    const selectedCase = process.env.RTC_CHROMIUM_INTEROP_CASE;
    if (
      selectedCase !== undefined &&
      !cases.some(({ role, mode }) => selectedCase === `${role}-${mode}`)
    ) {
      throw new Error(
        `RTC_CHROMIUM_INTEROP_CASE must be one of ${cases
          .map(({ role, mode }) => `${role}-${mode}`)
          .join(", ")}`,
      );
    }
    for (const { role, mode } of cases) {
      if (
        selectedCase !== undefined &&
        selectedCase !== `${role}-${mode}`
      ) {
        continue;
      }
      await runCase(browser, fixtureDirectory, role, mode);
    }
  } finally {
    await browser.close();
    if (keepArtifacts) {
      console.error(`Chromium interop artifacts kept at ${fixtureDirectory}`);
    } else {
      await rm(fixtureDirectory, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
