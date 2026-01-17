import type { CompressAlgo, EncryptAlgo } from "./types";

export const XFERKIT_VERSION = 1 as const;

export type PayloadFormat = "json" | "bin";

export type BinaryType =
  | "ArrayBuffer"
  | "DataView"
  | "Uint8Array"
  | "Uint8ClampedArray"
  | "Int8Array"
  | "Uint16Array"
  | "Int16Array"
  | "Uint32Array"
  | "Int32Array"
  | "Float32Array"
  | "Float64Array"
  | "BigInt64Array"
  | "BigUint64Array";

export type Frame = DataFrame | AckFrame | NackFrame;

export type DataFrame = {
  __xferkit: 1;
  v: typeof XFERKIT_VERSION;
  kind: "data";
  channel: string;
  id: string;
  mode: "structured" | "binary";
  ack?: 1;
  payload: unknown;
  part?: {
    index: number;
    total: number;
  };
  format?: PayloadFormat;
  binType?: BinaryType;
  codec?: {
    compress?: CompressAlgo;
    encrypt?: EncryptAlgo;
  };
  iv?: ArrayBuffer;
};

export type AckFrame = {
  __xferkit: 1;
  v: typeof XFERKIT_VERSION;
  kind: "ack";
  channel: string;
  id: string;
};

export type NackFrame = {
  __xferkit: 1;
  v: typeof XFERKIT_VERSION;
  kind: "nack";
  channel: string;
  id: string;
  reason?: string;
};

export function isFrame(value: unknown): value is Frame {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Frame;
  return candidate.__xferkit === 1 && candidate.v === XFERKIT_VERSION;
}

export function isDataFrame(frame: Frame): frame is DataFrame {
  return frame.kind === "data";
}

export function isAckFrame(frame: Frame): frame is AckFrame {
  return frame.kind === "ack";
}

export function isNackFrame(frame: Frame): frame is NackFrame {
  return frame.kind === "nack";
}
