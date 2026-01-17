import type { BinaryType } from "./envelope.js";

const TAG = "$xferkit";

type TaggedValue =
  | { [TAG]: "ArrayBuffer"; data: string }
  | { [TAG]: BinaryType; data: string }
  | { [TAG]: "Date"; value: string }
  | { [TAG]: "Map"; entries: [unknown, unknown][] }
  | { [TAG]: "Set"; values: unknown[] }
  | { [TAG]: "BigInt"; value: string };

export function stringifyWithTags(value: unknown): string {
  return JSON.stringify(value, replacer);
}

export function parseWithTags(text: string): unknown {
  return JSON.parse(text, reviver);
}

function replacer(_key: string, value: unknown): unknown {
  if (value instanceof ArrayBuffer) {
    return { [TAG]: "ArrayBuffer", data: bytesToBase64(new Uint8Array(value)) };
  }

  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const type = getBinaryType(view);
    return { [TAG]: type, data: bytesToBase64(bytes) };
  }

  if (value instanceof Map) {
    return { [TAG]: "Map", entries: Array.from(value.entries()) };
  }

  if (value instanceof Set) {
    return { [TAG]: "Set", values: Array.from(value.values()) };
  }

  if (value instanceof Date) {
    return { [TAG]: "Date", value: value.toISOString() };
  }

  if (typeof value === "bigint") {
    return { [TAG]: "BigInt", value: value.toString() };
  }

  return value;
}

function reviver(_key: string, value: unknown): unknown {
  if (!value || typeof value !== "object") {
    return value;
  }

  const tagged = value as TaggedValue;
  if (!(TAG in tagged)) {
    return value;
  }

  const tag = (tagged as any)[TAG] as TaggedValue[typeof TAG];
  switch (tag) {
    case "ArrayBuffer": {
      const payload = tagged as { [TAG]: "ArrayBuffer"; data: string };
      const bytes = base64ToBytes(payload.data);
      return bytes.buffer;
    }
    case "Date": {
      const payload = tagged as { [TAG]: "Date"; value: string };
      return new Date(payload.value);
    }
    case "Map": {
      const payload = tagged as { [TAG]: "Map"; entries: [unknown, unknown][] };
      return new Map(payload.entries);
    }
    case "Set": {
      const payload = tagged as { [TAG]: "Set"; values: unknown[] };
      return new Set(payload.values);
    }
    case "BigInt":
      if (typeof BigInt === "undefined") {
        const payload = tagged as { [TAG]: "BigInt"; value: string };
        return payload.value;
      }
      return BigInt((tagged as { [TAG]: "BigInt"; value: string }).value);
    default: {
      const payload = tagged as { [TAG]: BinaryType; data: string };
      const type = payload[TAG];
      const bytes = base64ToBytes(payload.data);
      return buildTypedView(type, bytes);
    }
  }
}

function getBinaryType(view: ArrayBufferView): BinaryType {
  const name = view.constructor?.name;
  if (name === "DataView") {
    return "DataView";
  }
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

function buildTypedView(
  type: BinaryType,
  bytes: Uint8Array
): ArrayBuffer | ArrayBufferView {
  const buffer = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
  if (type === "ArrayBuffer") {
    return buffer;
  }
  if (type === "DataView") {
    return new DataView(buffer);
  }
  const ctor = getTypedArrayConstructor(type);
  if (!ctor) {
    return new Uint8Array(buffer);
  }
  return new ctor(buffer);
}

type TypedArrayCtor = new (buffer: ArrayBuffer) => ArrayBufferView;

function getTypedArrayConstructor(type: BinaryType): TypedArrayCtor | null {
  switch (type) {
    case "Uint8Array":
      return Uint8Array;
    case "Uint8ClampedArray":
      return Uint8ClampedArray;
    case "Int8Array":
      return Int8Array;
    case "Uint16Array":
      return Uint16Array;
    case "Int16Array":
      return Int16Array;
    case "Uint32Array":
      return Uint32Array;
    case "Int32Array":
      return Int32Array;
    case "Float32Array":
      return Float32Array;
    case "Float64Array":
      return Float64Array;
    case "BigInt64Array":
      return typeof BigInt64Array !== "undefined" ? BigInt64Array : null;
    case "BigUint64Array":
      return typeof BigUint64Array !== "undefined" ? BigUint64Array : null;
    default:
      return null;
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === "undefined") {
    throw new Error("btoa is not available in this environment.");
  }
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  if (typeof atob === "undefined") {
    throw new Error("atob is not available in this environment.");
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
