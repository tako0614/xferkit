export type CompressAlgo = "gzip" | "deflate" | "brotli";
export type EncryptAlgo = "aes-gcm";

export interface XferCompressOptions {
  algo: CompressAlgo;
  level?: number;
}

export interface XferEncryptOptions {
  algo: EncryptAlgo;
  key: CryptoKey;
  ivLength?: number;
}

export interface XferCodecOptions {
  compress?: XferCompressOptions;
  encrypt?: XferEncryptOptions;
}

export interface XferTransferOptions {
  auto?: boolean;
}

export interface XferOptions {
  codec?: XferCodecOptions;
  transfer?: XferTransferOptions;
}

export type XferEvent = "message" | "error";
export type XferHandler = (payload: unknown) => void;

export type XferTarget = {
  postMessage: (message: unknown, transfer?: Transferable[]) => void;
  addEventListener: (
    type: "message" | "messageerror",
    listener: (event: MessageEvent) => void
  ) => void;
  removeEventListener?: (
    type: "message" | "messageerror",
    listener: (event: MessageEvent) => void
  ) => void;
};

type Envelope = {
  __xferkit: 1;
  format: "json" | "bin";
  binKind?: "arraybuffer" | "uint8array";
  codec?: {
    compress?: CompressAlgo;
    encrypt?: EncryptAlgo;
  };
  iv?: ArrayBuffer;
  payload: ArrayBuffer;
};

export interface Xfer {
  send(data: unknown): Promise<void>;
  on(event: XferEvent, handler: XferHandler): () => void;
  close(): void;
}

export function createXfer(target: XferTarget, options: XferOptions = {}): Xfer {
  const listeners: Record<XferEvent, Set<XferHandler>> = {
    message: new Set(),
    error: new Set(),
  };

  const onMessage = (event: MessageEvent) => {
    void handleIncoming(event.data);
  };

  const onError = (event: MessageEvent) => {
    emit("error", event);
  };

  target.addEventListener("message", onMessage);
  target.addEventListener("messageerror", onError);

  const handleIncoming = async (data: unknown) => {
    if (!isEnvelope(data)) {
      emit("message", data);
      return;
    }

    try {
      const decoded = await decodeEnvelope(data, options.codec);
      emit("message", decoded);
    } catch (err) {
      emit("error", err);
    }
  };

  const emit = (event: XferEvent, payload: unknown) => {
    for (const handler of listeners[event]) {
      try {
        handler(payload);
      } catch (err) {
        if (event !== "error") {
          listeners.error.forEach((fn) => fn(err));
        }
      }
    }
  };

  const send = async (data: unknown) => {
    const codec = options.codec;
    const hasCodec = Boolean(codec?.compress || codec?.encrypt);
    if (!hasCodec) {
      const transferList = options.transfer?.auto
        ? collectTransferables(data)
        : undefined;
      postMessage(target, data, transferList);
      return;
    }

    const envelope = await encodeEnvelope(data, codec ?? {});
    postMessage(target, envelope, [envelope.payload]);
  };

  const on = (event: XferEvent, handler: XferHandler) => {
    listeners[event].add(handler);
    return () => {
      listeners[event].delete(handler);
    };
  };

  const close = () => {
    target.removeEventListener?.("message", onMessage);
    target.removeEventListener?.("messageerror", onError);
    listeners.message.clear();
    listeners.error.clear();
  };

  return { send, on, close };
}

function isEnvelope(value: unknown): value is Envelope {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Envelope;
  return candidate.__xferkit === 1 && !!candidate.payload;
}

function postMessage(
  target: XferTarget,
  message: unknown,
  transferList?: Transferable[]
) {
  if (!transferList || transferList.length === 0 || !supportsTransfer(target)) {
    target.postMessage(message);
    return;
  }
  target.postMessage(message, transferList);
}

function supportsTransfer(target: XferTarget): boolean {
  if (
    typeof BroadcastChannel !== "undefined" &&
    target instanceof BroadcastChannel
  ) {
    return false;
  }
  return true;
}

async function encodeEnvelope(
  data: unknown,
  codec: XferCodecOptions
): Promise<Envelope> {
  const { bytes, format, binKind } = encodePayload(data);
  let output = bytes;

  if (codec.compress) {
    output = await compressBytes(codec.compress.algo, output);
  }

  let iv: Uint8Array | undefined;
  if (codec.encrypt) {
    const encrypted = await encryptBytes(output, codec.encrypt);
    output = encrypted.bytes;
    iv = encrypted.iv;
  }

  return {
    __xferkit: 1,
    format,
    binKind,
    codec: {
      compress: codec.compress?.algo,
      encrypt: codec.encrypt?.algo,
    },
    iv: iv ? toArrayBuffer(iv) : undefined,
    payload: toArrayBuffer(output),
  };
}

async function decodeEnvelope(
  envelope: Envelope,
  codec: XferCodecOptions | undefined
): Promise<unknown> {
  let output = new Uint8Array(envelope.payload);

  if (envelope.codec?.encrypt) {
    const decryptKey = codec?.encrypt?.key;
    if (!decryptKey) {
      throw new Error("Missing decryption key for encrypted message.");
    }
    if (!envelope.iv) {
      throw new Error("Missing iv for encrypted message.");
    }
    output = await decryptBytes(
      output,
      { algo: envelope.codec.encrypt, key: decryptKey },
      new Uint8Array(envelope.iv)
    );
  }

  if (envelope.codec?.compress) {
    output = await decompressBytes(envelope.codec.compress, output);
  }

  return decodePayload(output, envelope.format, envelope.binKind);
}

function encodePayload(data: unknown): {
  bytes: Uint8Array;
  format: "json" | "bin";
  binKind?: "arraybuffer" | "uint8array";
} {
  if (data instanceof ArrayBuffer) {
    return { bytes: new Uint8Array(data), format: "bin", binKind: "arraybuffer" };
  }

  if (ArrayBuffer.isView(data)) {
    const view = new Uint8Array(
      data.buffer,
      data.byteOffset,
      data.byteLength
    );
    return { bytes: view, format: "bin", binKind: "uint8array" };
  }

  const json = JSON.stringify(data);
  const bytes = new TextEncoder().encode(json);
  return { bytes, format: "json" };
}

function decodePayload(
  bytes: Uint8Array,
  format: "json" | "bin",
  binKind?: "arraybuffer" | "uint8array"
): unknown {
  if (format === "bin") {
    if (binKind === "arraybuffer") {
      return toArrayBuffer(bytes);
    }
    return bytes;
  }

  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text) as unknown;
}

async function compressBytes(
  algo: CompressAlgo,
  bytes: Uint8Array
): Promise<Uint8Array> {
  const CompressionStreamCtor = (globalThis as any).CompressionStream as
    | (new (format: string) => { readable: ReadableStream<Uint8Array> })
    | undefined;
  if (!CompressionStreamCtor) {
    throw new Error("CompressionStream is not available in this environment.");
  }

  const stream = new Blob([bytes]).stream().pipeThrough(
    new CompressionStreamCtor(algo)
  );
  return streamToUint8Array(stream);
}

async function decompressBytes(
  algo: CompressAlgo,
  bytes: Uint8Array
): Promise<Uint8Array> {
  const DecompressionStreamCtor = (globalThis as any).DecompressionStream as
    | (new (format: string) => { readable: ReadableStream<Uint8Array> })
    | undefined;
  if (!DecompressionStreamCtor) {
    throw new Error(
      "DecompressionStream is not available in this environment."
    );
  }

  const stream = new Blob([bytes]).stream().pipeThrough(
    new DecompressionStreamCtor(algo)
  );
  return streamToUint8Array(stream);
}

async function encryptBytes(
  bytes: Uint8Array,
  options: XferEncryptOptions
): Promise<{ bytes: Uint8Array; iv: Uint8Array }> {
  if (options.algo !== "aes-gcm") {
    throw new Error(`Unsupported encryption algorithm: ${options.algo}`);
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }

  const iv = globalThis.crypto.getRandomValues(
    new Uint8Array(options.ivLength ?? 12)
  );
  const encrypted = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    options.key,
    bytes
  );
  return { bytes: new Uint8Array(encrypted), iv };
}

async function decryptBytes(
  bytes: Uint8Array,
  options: { algo: EncryptAlgo; key: CryptoKey },
  iv: Uint8Array
): Promise<Uint8Array> {
  if (options.algo !== "aes-gcm") {
    throw new Error(`Unsupported encryption algorithm: ${options.algo}`);
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }

  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    options.key,
    bytes
  );
  return new Uint8Array(decrypted);
}

async function streamToUint8Array(
  stream: ReadableStream<Uint8Array>
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer;
  }
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function collectTransferables(value: unknown): Transferable[] {
  const transferables = new Set<Transferable>();
  const seen = new WeakSet<object>();

  const visit = (val: unknown) => {
    if (!val || typeof val !== "object") {
      return;
    }

    if (val instanceof ArrayBuffer) {
      transferables.add(val);
      return;
    }

    if (ArrayBuffer.isView(val)) {
      transferables.add(val.buffer);
      return;
    }

    if (typeof MessagePort !== "undefined" && val instanceof MessagePort) {
      transferables.add(val);
      return;
    }

    if (typeof ImageBitmap !== "undefined" && val instanceof ImageBitmap) {
      transferables.add(val);
      return;
    }

    if (
      typeof OffscreenCanvas !== "undefined" &&
      val instanceof OffscreenCanvas
    ) {
      transferables.add(val);
      return;
    }

    if (seen.has(val)) {
      return;
    }
    seen.add(val);

    if (Array.isArray(val)) {
      for (const item of val) {
        visit(item);
      }
      return;
    }

    if (val instanceof Map) {
      for (const [key, item] of val) {
        visit(key);
        visit(item);
      }
      return;
    }

    if (val instanceof Set) {
      for (const item of val) {
        visit(item);
      }
      return;
    }

    for (const item of Object.values(val as Record<string, unknown>)) {
      visit(item);
    }
  };

  visit(value);
  return Array.from(transferables);
}
