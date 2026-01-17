import { MessageChannel } from "worker_threads";
import { webcrypto } from "crypto";
import { createXfer } from "../dist/index.js";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

const { port1, port2 } = new MessageChannel();

const a = createXfer(wrapPort(port1), {
  channelId: "xfer",
  chunk: { maxBytes: 4 },
  reliability: { ackMode: "chunk", maxRetries: 2 },
});

const b = createXfer(wrapPort(port2), {
  channelId: "xfer",
  chunk: { maxBytes: 4 },
  reliability: { ackMode: "chunk", maxRetries: 2 },
});

const received = [];
const streams = [];

b.on("message", (msg) => {
  received.push(msg);
});

b.on("stream", (info) => {
  streams.push(info);
  const { stream } = info;
  const reader = stream.getReader();
  void (async () => {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      received.push({ streamChunk: value });
    }
  })();
});

await a.send({ hello: "world" });
await a.send(new Uint8Array([1, 2, 3, 4, 5, 6, 7]));

if (typeof ReadableStream !== "undefined") {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([9, 9, 9]));
      controller.enqueue(new Uint8Array([8, 8, 8]));
      controller.close();
    },
  });
  await a.sendStream(stream, { meta: { name: "smoke" } });
}

await wait(200);

console.log("received", received.length);
console.log("streams", streams.length);

a.close();
b.close();
port1.close();
port2.close();
