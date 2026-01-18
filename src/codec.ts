import type { BinaryType, PayloadFormat } from "./envelope.js";
import type {
  AuthAlgo,
  CompressAlgo,
  EncryptAlgo,
  XferAuthOptions,
  XferCodecOptions,
  XferEncryptOptions,
  XferKeyring,
} from "./types.js";
import { parseWithTags, stringifyWithTags } from "./serializer.js";

export type BinaryPayload = {
  bytes: Uint8Array;
  format: PayloadFormat;
  binType?: BinaryType;
};

export function encodeBinaryPayload(data: unknown): BinaryPayload {
  if (data instanceof ArrayBuffer) {
    return {
      bytes: new Uint8Array(data),
      format: "bin",
      binType: "ArrayBuffer",
    };
  }

  if (
    typeof SharedArrayBuffer !== "undefined" &&
    data instanceof SharedArrayBuffer
  ) {
    return {
      bytes: new Uint8Array(data),
      format: "bin",
      binType: "ArrayBuffer",
    };
  }

  if (ArrayBuffer.isView(data)) {
    const view = data as ArrayBufferView;
    return {
      bytes: new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
      format: "bin",
      binType: resolveBinaryType(view),
    };
  }

  try {
    const json = stringifyWithTags(data);
    return {
      bytes: new TextEncoder().encode(json),
      format: "json",
    };
  } catch (err) {
    throw new Error(
      `Failed to encode payload: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// Type definitions for CompressionStream and DecompressionStream
interface CompressionStreamConstructor {
  new (format: string): {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  };
}

interface DecompressionStreamConstructor {
  new (format: string): {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  };
}

interface GlobalWithCompression {
  CompressionStream?: CompressionStreamConstructor;
  DecompressionStream?: DecompressionStreamConstructor;
}

export function decodeBinaryPayload(
  bytes: Uint8Array,
  format: PayloadFormat,
  binType?: BinaryType
): unknown {
  if (format === "bin") {
    const buffer = toArrayBuffer(bytes);
    if (binType && binType !== "ArrayBuffer") {
      return reviveBinaryView(buffer, binType);
    }
    return buffer;
  }

  try {
    const text = new TextDecoder().decode(bytes);
    return parseWithTags(text);
  } catch (err) {
    throw new Error(
      `Failed to decode payload: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

export async function applyCodecEncode(
  bytes: Uint8Array,
  codec: XferCodecOptions | undefined
): Promise<{ bytes: Uint8Array; iv?: Uint8Array; codec?: CodecInfo }> {
  let output = bytes;
  let codecInfo: CodecInfo | undefined;
  if (codec?.compress) {
    const compressed = await compressBytes(
      codec.compress.algo,
      output,
      codec.compress.fallback
    );
    if (compressed.applied) {
      output = compressed.bytes;
      codecInfo = { ...codecInfo, compress: codec.compress.algo };
    }
  }

  if (codec?.encrypt) {
    const resolved = resolveEncryptOptions(codec.encrypt);
    const encrypted = await encryptBytes(output, resolved);
    output = encrypted.bytes;
    codecInfo = {
      ...codecInfo,
      encrypt: codec.encrypt.algo,
      keyId: resolved.keyId,
    };
    return { bytes: output, iv: encrypted.iv, codec: codecInfo };
  }

  return { bytes: output, codec: codecInfo };
}

export async function applyCodecDecode(
  bytes: Uint8Array,
  codecInfo: CodecInfo | undefined,
  codecOptions: XferCodecOptions | undefined,
  iv?: Uint8Array
): Promise<Uint8Array> {
  let output = bytes;
  if (codecInfo?.encrypt) {
    const key = resolveDecryptKey(codecOptions?.encrypt, codecInfo.keyId);
    if (!key) {
      throw new Error("Missing decryption key for encrypted payload.");
    }
    if (!iv) {
      throw new Error("Missing iv for encrypted payload.");
    }
    output = await decryptBytes(output, codecInfo.encrypt, key, iv);
  }

  if (codecInfo?.compress) {
    output = await decompressBytes(codecInfo.compress, output);
  }

  return output;
}

export type CodecInfo = {
  compress?: CompressAlgo;
  encrypt?: EncryptAlgo;
  keyId?: string;
  auth?: AuthInfo;
};

export type AuthInfo = {
  algo: AuthAlgo;
  keyId?: string;
};

export async function createAuthTag(
  bytes: Uint8Array,
  options: XferAuthOptions | undefined,
  encrypted: boolean
): Promise<{ auth: AuthInfo; tag: Uint8Array } | null> {
  if (!options) {
    return null;
  }
  if (encrypted && options.skipIfEncrypted !== false && !options.required) {
    return null;
  }
  const algo = options.algo ?? "hmac-sha-256";
  const keyInfo = normalizeKey(options.key, options.keyId, true);
  const tag = await hmacSign(bytes, keyInfo.key, algo);
  return { auth: { algo, keyId: keyInfo.keyId }, tag };
}

export async function verifyAuthTag(
  bytes: Uint8Array,
  auth: AuthInfo | undefined,
  tag: Uint8Array | undefined,
  options: XferAuthOptions | undefined,
  encrypted: boolean
): Promise<void> {
  if (!auth) {
    if (options?.required) {
      throw new Error("Missing auth tag for payload.");
    }
    return;
  }
  if (!tag) {
    throw new Error("Missing auth tag bytes.");
  }
  if (encrypted && options?.skipIfEncrypted !== false && !options?.required) {
    return;
  }
  const key = resolveAuthKey(options, auth.keyId);
  if (!key) {
    throw new Error("Missing auth key for payload.");
  }
  const ok = await hmacVerify(bytes, tag, key, auth.algo);
  if (!ok) {
    throw new Error("Auth tag verification failed.");
  }
}

function reviveBinaryView(buffer: ArrayBuffer, binType: BinaryType): ArrayBufferView {
  switch (binType) {
    case "DataView":
      return new DataView(buffer);
    case "Uint8Array":
      return new Uint8Array(buffer);
    case "Uint8ClampedArray":
      return new Uint8ClampedArray(buffer);
    case "Int8Array":
      return new Int8Array(buffer);
    case "Uint16Array":
      return new Uint16Array(buffer);
    case "Int16Array":
      return new Int16Array(buffer);
    case "Uint32Array":
      return new Uint32Array(buffer);
    case "Int32Array":
      return new Int32Array(buffer);
    case "Float32Array":
      return new Float32Array(buffer);
    case "Float64Array":
      return new Float64Array(buffer);
    case "BigInt64Array":
      if (typeof BigInt64Array === "undefined") {
        return new Uint8Array(buffer);
      }
      return new BigInt64Array(buffer);
    case "BigUint64Array":
      if (typeof BigUint64Array === "undefined") {
        return new Uint8Array(buffer);
      }
      return new BigUint64Array(buffer);
    default:
      return new Uint8Array(buffer);
  }
}

function resolveBinaryType(view: ArrayBufferView): BinaryType {
  const name = view.constructor?.name;
  if (name === "DataView") return "DataView";
  if (name === "Uint8Array") return "Uint8Array";
  if (name === "Uint8ClampedArray") return "Uint8ClampedArray";
  if (name === "Int8Array") return "Int8Array";
  if (name === "Uint16Array") return "Uint16Array";
  if (name === "Int16Array") return "Int16Array";
  if (name === "Uint32Array") return "Uint32Array";
  if (name === "Int32Array") return "Int32Array";
  if (name === "Float32Array") return "Float32Array";
  if (name === "Float64Array") return "Float64Array";
  if (name === "BigInt64Array") return "BigInt64Array";
  if (name === "BigUint64Array") return "BigUint64Array";
  return "Uint8Array";
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer;
  }
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

async function compressBytes(
  algo: CompressAlgo,
  bytes: Uint8Array,
  fallback?: "error" | "skip"
): Promise<{ bytes: Uint8Array; applied: boolean }> {
  const global_ = globalThis as typeof globalThis & Partial<GlobalWithCompression>;
  const CompressionStreamCtor = global_.CompressionStream;

  if (!CompressionStreamCtor) {
    if (fallback === "skip") {
      return { bytes, applied: false };
    }
    throw new Error("CompressionStream is not available in this environment.");
  }

  try {
    const stream = new Blob([bytes])
      .stream()
      .pipeThrough(new CompressionStreamCtor(algo));

    return { bytes: await streamToUint8Array(stream), applied: true };
  } catch (err) {
    throw new Error(
      `Compression failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function decompressBytes(
  algo: CompressAlgo,
  bytes: Uint8Array
): Promise<Uint8Array> {
  const global_ = globalThis as typeof globalThis & Partial<GlobalWithCompression>;
  const DecompressionStreamCtor = global_.DecompressionStream;

  if (!DecompressionStreamCtor) {
    throw new Error(
      "DecompressionStream is not available in this environment."
    );
  }

  try {
    const stream = new Blob([bytes])
      .stream()
      .pipeThrough(new DecompressionStreamCtor(algo));

    return streamToUint8Array(stream);
  } catch (err) {
    throw new Error(
      `Decompression failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

async function encryptBytes(
  bytes: Uint8Array,
  options: { algo: EncryptAlgo; key: CryptoKey; keyId?: string; ivLength?: number }
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
  algo: EncryptAlgo,
  key: CryptoKey,
  iv: Uint8Array
): Promise<Uint8Array> {
  if (algo !== "aes-gcm") {
    throw new Error(`Unsupported encryption algorithm: ${algo}`);
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }

  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    bytes
  );
  return new Uint8Array(decrypted);
}

async function hmacSign(
  bytes: Uint8Array,
  key: CryptoKey,
  algo: AuthAlgo
): Promise<Uint8Array> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  const hash = algo === "hmac-sha-256" ? "SHA-256" : "SHA-256";
  const signature = await globalThis.crypto.subtle.sign(
    { name: "HMAC", hash },
    key,
    bytes
  );
  return new Uint8Array(signature);
}

async function hmacVerify(
  bytes: Uint8Array,
  tag: Uint8Array,
  key: CryptoKey,
  algo: AuthAlgo
): Promise<boolean> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  const hash = algo === "hmac-sha-256" ? "SHA-256" : "SHA-256";
  return globalThis.crypto.subtle.verify(
    { name: "HMAC", hash },
    key,
    tag,
    bytes
  );
}

function resolveEncryptOptions(
  options: XferEncryptOptions
): { algo: EncryptAlgo; key: CryptoKey; keyId?: string; ivLength?: number } {
  const keyInfo = normalizeKey(options.key, options.keyId, true);
  return {
    algo: options.algo,
    key: keyInfo.key,
    keyId: keyInfo.keyId,
    ivLength: options.ivLength,
  };
}

function resolveDecryptKey(
  options: XferEncryptOptions | undefined,
  keyId: string | undefined
): CryptoKey | null {
  if (!options) {
    return null;
  }
  if (isKeyring(options.key)) {
    const ring = options.key;
    const effectiveId = keyId ?? options.keyId;
    if (effectiveId) {
      if (ring.keys && ring.keys[effectiveId]) {
        const key = ring.keys[effectiveId];
        if (key && typeof key === "object" && key instanceof CryptoKey) {
          return key;
        }
        return null;
      }
      if (ring.currentId === effectiveId) {
        return ring.current;
      }
      return null;
    }
    return ring.current;
  }
  return options.key;
}

function resolveAuthKey(
  options: XferAuthOptions | undefined,
  keyId: string | undefined
): CryptoKey | null {
  if (!options) {
    return null;
  }
  if (isKeyring(options.key)) {
    const ring = options.key;
    const effectiveId = keyId ?? options.keyId;
    if (effectiveId) {
      if (ring.keys && ring.keys[effectiveId]) {
        const key = ring.keys[effectiveId];
        if (key && typeof key === "object" && key instanceof CryptoKey) {
          return key;
        }
        return null;
      }
      if (ring.currentId === effectiveId) {
        return ring.current;
      }
      return null;
    }
    return ring.current;
  }
  return options.key;
}

function normalizeKey(
  key: CryptoKey | XferKeyring,
  keyId: string | undefined,
  strict: boolean
): { key: CryptoKey; keyId?: string } {
  if (isKeyring(key)) {
    if (keyId) {
      if (key.keys && key.keys[keyId]) {
        return { key: key.keys[keyId], keyId };
      }
      if (key.currentId === keyId) {
        return { key: key.current, keyId };
      }
      if (strict) {
        throw new Error(`Missing key for keyId: ${keyId}`);
      }
    }
    return { key: key.current, keyId: key.currentId ?? keyId };
  }
  return { key, keyId };
}

function isKeyring(value: CryptoKey | XferKeyring): value is XferKeyring {
  return (
    value !== null &&
    typeof value === "object" &&
    "current" in value &&
    typeof value.current !== "undefined"
  );
}

async function streamToUint8Array(
  stream: ReadableStream<Uint8Array>
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
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
  } catch (err) {
    throw new Error(
      `Stream reading failed: ${err instanceof Error ? err.message : String(err)}`
    );
  } finally {
    reader.releaseLock();
  }
}
