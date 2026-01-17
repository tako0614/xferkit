import type { BinaryType, PayloadFormat } from "./envelope";
import type { CompressAlgo, EncryptAlgo, XferCodecOptions } from "./types";
import { parseWithTags, stringifyWithTags } from "./serializer";

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

  if (ArrayBuffer.isView(data)) {
    const view = data as ArrayBufferView;
    return {
      bytes: new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
      format: "bin",
      binType: resolveBinaryType(view),
    };
  }

  const json = stringifyWithTags(data);
  return {
    bytes: new TextEncoder().encode(json),
    format: "json",
  };
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

  const text = new TextDecoder().decode(bytes);
  return parseWithTags(text);
}

export async function applyCodecEncode(
  bytes: Uint8Array,
  codec: XferCodecOptions | undefined
): Promise<{ bytes: Uint8Array; iv?: Uint8Array; codec?: CodecInfo }> {
  let output = bytes;
  let codecInfo: CodecInfo | undefined;
  if (codec?.compress) {
    output = await compressBytes(codec.compress.algo, output);
    codecInfo = { ...codecInfo, compress: codec.compress.algo };
  }

  if (codec?.encrypt) {
    const encrypted = await encryptBytes(output, codec.encrypt);
    output = encrypted.bytes;
    codecInfo = { ...codecInfo, encrypt: codec.encrypt.algo };
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
    const key = codecOptions?.encrypt?.key;
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
};

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
  options: { algo: EncryptAlgo; key: CryptoKey; ivLength?: number }
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
