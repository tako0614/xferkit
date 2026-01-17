import { MessageChannel } from "worker_threads";
import { webcrypto } from "crypto";
import { createXfer } from "../dist/index.js";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}
process.on("unhandledRejection", () => {});

class MemoryStorage {
  constructor() {
    this.store = new Map();
  }
  get length() {
    return this.store.size;
  }
  clear() {
    this.store.clear();
  }
  getItem(key) {
    const value = this.store.get(key);
    return value === undefined ? null : value;
  }
  key(index) {
    return Array.from(this.store.keys())[index] ?? null;
  }
  removeItem(key) {
    this.store.delete(key);
  }
  setItem(key, value) {
    this.store.set(key, String(value));
  }
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const splitBytes = (bytes, size) => {
  const chunks = [];
  for (let offset = 0; offset < bytes.byteLength; offset += size) {
    chunks.push(bytes.subarray(offset, offset + size));
  }
  return chunks;
};

const concatBytes = (chunks) => {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.byteLength;
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
};

const streamFromBytes = (bytes, size) =>
  new ReadableStream({
    start(controller) {
      for (const chunk of splitBytes(bytes, size)) {
        controller.enqueue(chunk);
      }
      controller.close();
    },
  });

const wrapPort = (port) => {
  const handlers = new Map();
  const on = (event, fn) => port.on(event, fn);
  const off = (event, fn) => {
    if (typeof port.off === "function") {
      port.off(event, fn);
    } else {
      port.removeListener(event, fn);
    }
  };
  return {
    postMessage(message, transfer) {
      port.postMessage(message, transfer);
    },
    addEventListener(type, listener) {
      if (type === "message") {
        const handler = (data) => listener({ data });
        handlers.set(listener, { type: "message", handler });
        on("message", handler);
      } else if (type === "messageerror") {
        const handler = (data) => listener({ data });
        handlers.set(listener, { type: "messageerror", handler });
        on("messageerror", handler);
      }
    },
    removeEventListener(_type, listener) {
      const entry = handlers.get(listener);
      if (!entry) return;
      off(entry.type, entry.handler);
      handlers.delete(listener);
    },
  };
};

const authKey = await globalThis.crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode("resume-secret"),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"]
);

const storageA = new MemoryStorage();
const storageB = new MemoryStorage();
const streamPayload = new TextEncoder().encode("resume-stream-payload");
const streamChunkSize = 4;
const streamKey = "resume-stream";
const buildStream = (offset = 0) => {
  const safeOffset = Math.min(offset, streamPayload.byteLength);
  return streamFromBytes(streamPayload.subarray(safeOffset), streamChunkSize);
};

const deadTarget = {
  postMessage() {},
  addEventListener() {},
  removeEventListener() {},
};

const a1 = createXfer(deadTarget, {
  channelId: "xfer-resume",
  session: { id: "demo", storage: storageA, persistOutbound: true },
  codec: { auth: { key: authKey, required: true } },
  chunk: { maxBytes: 4 },
  reliability: {
    ackTimeoutMs: 10_000,
    maxRetries: 0,
    ackMode: "chunk",
    chunkWindowSize: 1,
  },
});

void a1.send({ kind: "resume", payload: "message" }).catch(() => {});

if (typeof ReadableStream !== "undefined") {
  const stream = buildStream();
  void a1
    .sendStream(stream, { meta: { name: "resume-stream" }, resumeKey: streamKey })
    .catch(() => {});
}

await wait(100);
a1.close();
await wait(50);
console.log("storedKeys", storageA.length);
const storedState = storageA.getItem("xferkit:demo");
if (storedState) {
  const parsed = JSON.parse(storedState);
  console.log("storedOutbound", Object.keys(parsed.outbound ?? {}).length);
  console.log("storedOutboundStreams", parsed.outboundStreams?.length ?? 0);
  console.log(
    "storedOutboundStreamStates",
    Object.keys(parsed.outboundStreamStates ?? {}).length
  );
}

const { port1, port2 } = new MessageChannel();

const b = createXfer(wrapPort(port2), {
  channelId: "xfer-resume",
  session: { id: "demo-peer", storage: storageB, persistOutbound: true, persistInbound: true },
  codec: { auth: { key: authKey, required: true } },
  handshake: { auto: true },
  chunk: { maxBytes: 4 },
  reliability: { ackMode: "chunk", maxRetries: 1 },
});

const a2 = createXfer(wrapPort(port1), {
  channelId: "xfer-resume",
  session: {
    id: "demo",
    storage: storageA,
    persistOutbound: true,
    persistInbound: true,
    streamResume: ({ key, offset }) =>
      key === streamKey ? buildStream(offset) : null,
  },
  codec: { auth: { key: authKey, required: true } },
  handshake: { auto: true },
  chunk: { maxBytes: 4 },
  reliability: { ackMode: "chunk", maxRetries: 1 },
});

const resumed = [];
const received = [];
const streamChunks = [];

a2.on("status", (status) => {
  if (status && status.type === "resume") {
    resumed.push(status.id);
  }
});

b.on("message", (msg) => {
  received.push(msg);
});

b.on("stream", (info) => {
  const { stream } = info;
  const reader = stream.getReader();
  void (async () => {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      streamChunks.push(value);
      received.push({ streamChunk: value });
    }
  })();
});

await wait(400);

const streamBytes = concatBytes(streamChunks);
console.log("resumed", resumed.length);
console.log("received", received.length);
console.log("streamBytes", streamBytes.byteLength);
console.log("streamMatch", streamBytes.byteLength === streamPayload.byteLength);

a2.close();
b.close();
port1.close();
port2.close();
