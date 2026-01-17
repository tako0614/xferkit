# xferkit

High-level message pipeline for postMessage/BroadcastChannel with:
- compression, encryption, and auth tags
- transferList auto extraction
- adaptive chunking with ack/retry and backpressure
- ordering controls
- stream send/receive
- optional ECDH handshake and session resume

This library targets browser Web APIs (Window, Worker, MessagePort, BroadcastChannel).

## Quick start

```ts
import { createXfer } from "xferkit";

const channel = createXfer(worker, {
  channelId: "xfer",
  codec: {
    compress: { algo: "brotli", fallback: "skip" },
    encrypt: { algo: "aes-gcm", key: myKey },
    auth: { key: myAuthKey },
  },
  chunk: { maxBytes: 256 * 1024 },
  reliability: {
    ackMode: "chunk",
    maxRetries: 3,
    maxInFlight: 8,
    order: "strict",
  },
});

channel.on("message", (msg) => {
  console.log("recv", msg);
});

await channel.send({ kind: "hello", payload: "world" });
```

## Auth tags

```ts
const channel = createXfer(worker, {
  codec: {
    encrypt: { algo: "aes-gcm", key: myKey },
    auth: { key: myAuthKey, required: true },
  },
});
```

## Handshake (ECDH)

```ts
const channel = createXfer(worker, {
  codec: { encrypt: { algo: "aes-gcm", key: fallbackKey } },
  handshake: { auto: true, curve: "P-256" },
});

await channel.handshake();
```

## Session resume

```ts
const channel = createXfer(worker, {
  session: {
    id: "chat-room",
    persistOutbound: true,
    persistInbound: true,
    ttlMs: 5 * 60_000,
  },
});
```

## Adaptive chunking

```ts
const channel = createXfer(worker, {
  chunk: {
    maxBytes: 256 * 1024,
    auto: { minBytes: 4096, maxBytes: 256 * 1024 },
  },
});
```

## Stream send/receive

```ts
const stream = new ReadableStream<Uint8Array>({
  start(controller) {
    controller.enqueue(new TextEncoder().encode("hello"));
    controller.enqueue(new TextEncoder().encode("world"));
    controller.close();
  },
});

await channel.sendStream(stream, { meta: { name: "demo" } });

channel.on("stream", (info) => {
  const { stream, meta } = info as { stream: ReadableStream<Uint8Array>; meta?: unknown };
  console.log("stream meta", meta);
  const reader = stream.getReader();
  void (async () => {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      console.log("chunk", value);
    }
  })();
});
```

## Keys and rotation

```ts
import {
  createKeyring,
  deriveKeyFromPassphrase,
  rotateKeyring,
} from "xferkit";

const salt = crypto.getRandomValues(new Uint8Array(16));
const key = await deriveKeyFromPassphrase("secret", salt);
let ring = createKeyring(key, "v1");

const nextKey = await deriveKeyFromPassphrase("secret-2", salt);
ring = rotateKeyring(ring, nextKey, "v2");

const channel = createXfer(worker, {
  codec: {
    encrypt: { algo: "aes-gcm", key: ring },
  },
});
```

## Notes
- `channelId` must match on both sides (default is "xfer").
- Compression uses `CompressionStream`/`DecompressionStream`; set `fallback: "skip"` to avoid errors.
- For BroadcastChannel, transferList is ignored by the platform.
