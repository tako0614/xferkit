import type { BinaryType } from "./envelope.js";
import { base64ToBytes, bytesToBase64 } from "./util.js";

const TAG = "$xferkit";

type TaggedValue =
  | { [TAG]: "Ref"; id: number }
  | { [TAG]: "Object"; id: number; value: Record<string, unknown> }
  | { [TAG]: "Array"; id: number; items: unknown[] }
  | { [TAG]: "ArrayBuffer"; id: number; data: string }
  | { [TAG]: BinaryType; id: number; data: string }
  | { [TAG]: "Date"; id: number; value: string }
  | { [TAG]: "Map"; id: number; entries: [unknown, unknown][] }
  | { [TAG]: "Set"; id: number; values: unknown[] }
  | { [TAG]: "BigInt"; value: string };

type EncodeState = {
  seen: WeakMap<object, number>;
  nextId: number;
};

export function stringifyWithTags(value: unknown): string {
  const state: EncodeState = { seen: new WeakMap(), nextId: 1 };
  const encoded = encodeValue(value, state);
  return JSON.stringify(encoded);
}

export function parseWithTags(text: string): unknown {
  const decoded = JSON.parse(text);
  const refs = new Map<number, unknown>();
  collectRefs(decoded, refs);
  return inflate(decoded, refs);
}

function encodeValue(value: unknown, state: EncodeState): unknown {
  if (typeof value === "bigint") {
    return { [TAG]: "BigInt", value: value.toString() };
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  const existing = state.seen.get(value);
  if (existing) {
    return { [TAG]: "Ref", id: existing };
  }

  const id = state.nextId;
  state.nextId += 1;
  state.seen.set(value, id);

  if (value instanceof ArrayBuffer) {
    return { [TAG]: "ArrayBuffer", id, data: bytesToBase64(new Uint8Array(value)) };
  }

  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const type = getBinaryType(view);
    return { [TAG]: type, id, data: bytesToBase64(bytes) };
  }

  if (value instanceof Map) {
    return {
      [TAG]: "Map",
      id,
      entries: Array.from(value.entries()).map(([k, v]) => [
        encodeValue(k, state),
        encodeValue(v, state),
      ]),
    };
  }

  if (value instanceof Set) {
    return {
      [TAG]: "Set",
      id,
      values: Array.from(value.values()).map((v) => encodeValue(v, state)),
    };
  }

  if (value instanceof Date) {
    return { [TAG]: "Date", id, value: value.toISOString() };
  }

  if (Array.isArray(value)) {
    return {
      [TAG]: "Array",
      id,
      items: value.map((item) => encodeValue(item, state)),
    };
  }

  const record: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    record[key] = encodeValue(entry, state);
  }
  return { [TAG]: "Object", id, value: record };
}

function collectRefs(node: unknown, refs: Map<number, unknown>) {
  if (!node || typeof node !== "object") {
    return;
  }
  const tagged = node as TaggedValue;
  if (!(TAG in tagged)) {
    return;
  }
  const tag = (tagged as any)[TAG] as TaggedValue[typeof TAG];
  if (tag === "Ref") {
    return;
  }
  if ("id" in tagged) {
    const id = tagged.id;
    if (!refs.has(id)) {
      switch (tag) {
        case "Array":
          refs.set(id, []);
          (tagged as { items: unknown[] }).items.forEach((item) =>
            collectRefs(item, refs)
          );
          break;
        case "Object":
          refs.set(id, {});
          Object.values((tagged as { value: Record<string, unknown> }).value).forEach(
            (value) => collectRefs(value, refs)
          );
          break;
        case "Map":
          refs.set(id, new Map());
          (tagged as { entries: [unknown, unknown][] }).entries.forEach(([k, v]) => {
            collectRefs(k, refs);
            collectRefs(v, refs);
          });
          break;
        case "Set":
          refs.set(id, new Set());
          (tagged as { values: unknown[] }).values.forEach((value) =>
            collectRefs(value, refs)
          );
          break;
        case "ArrayBuffer": {
          const payload = tagged as { data: string };
          refs.set(id, base64ToBytes(payload.data).buffer);
          break;
        }
        case "Date": {
          const payload = tagged as { value: string };
          refs.set(id, new Date(payload.value));
          break;
        }
        default: {
          if (tag === "BigInt") {
            return;
          }
          const payload = tagged as { data: string };
          const bytes = base64ToBytes(payload.data);
          refs.set(id, buildTypedView(tag as BinaryType, bytes));
          break;
        }
      }
    }
  }
}

function inflate(node: unknown, refs: Map<number, unknown>): unknown {
  if (!node || typeof node !== "object") {
    return node;
  }
  const tagged = node as TaggedValue;
  if (!(TAG in tagged)) {
    return node;
  }
  const tag = (tagged as any)[TAG] as TaggedValue[typeof TAG];
  switch (tag) {
    case "Ref": {
      return refs.get((tagged as { id: number }).id);
    }
    case "Object": {
      const payload = tagged as { id: number; value: Record<string, unknown> };
      const target = (refs.get(payload.id) as Record<string, unknown>) ?? {};
      for (const [key, value] of Object.entries(payload.value)) {
        target[key] = inflate(value, refs);
      }
      return target;
    }
    case "Array": {
      const payload = tagged as { id: number; items: unknown[] };
      const target = (refs.get(payload.id) as unknown[]) ?? [];
      target.length = 0;
      for (const item of payload.items) {
        target.push(inflate(item, refs));
      }
      return target;
    }
    case "Map": {
      const payload = tagged as { id: number; entries: [unknown, unknown][] };
      const target = (refs.get(payload.id) as Map<unknown, unknown>) ?? new Map();
      target.clear();
      for (const [key, value] of payload.entries) {
        target.set(inflate(key, refs), inflate(value, refs));
      }
      return target;
    }
    case "Set": {
      const payload = tagged as { id: number; values: unknown[] };
      const target = (refs.get(payload.id) as Set<unknown>) ?? new Set();
      target.clear();
      for (const value of payload.values) {
        target.add(inflate(value, refs));
      }
      return target;
    }
    case "Date": {
      return refs.get((tagged as { id: number }).id);
    }
    case "ArrayBuffer":
      return refs.get((tagged as { id: number }).id);
    case "BigInt": {
      if (typeof BigInt === "undefined") {
        return (tagged as { value: string }).value;
      }
      return BigInt((tagged as { value: string }).value);
    }
    default: {
      return refs.get((tagged as { id: number }).id);
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
