import type { AuthAlgo, CompressAlgo, EncryptAlgo } from "./types.js";

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

export type Frame = DataFrame | AckFrame | NackFrame | ControlFrame;

export type DataFrame = {
  __xferkit: 1;
  v: typeof XFERKIT_VERSION;
  kind: "data";
  channel: string;
  id: string;
  seq?: number;
  mode: "structured" | "binary";
  ack?: 1;
  ackMode?: "message" | "chunk";
  payload: unknown;
  part?: {
    index: number;
    total: number;
  };
  stream?: {
    id: string;
    seq: number;
    done?: 1;
    meta?: unknown;
  };
  format?: PayloadFormat;
  binType?: BinaryType;
  codec?: {
    compress?: CompressAlgo;
    encrypt?: EncryptAlgo;
    keyId?: string;
  };
  auth?: {
    algo: AuthAlgo;
    keyId?: string;
  };
  authTag?: ArrayBuffer;
  iv?: ArrayBuffer;
};

export type AckFrame = {
  __xferkit: 1;
  v: typeof XFERKIT_VERSION;
  kind: "ack";
  channel: string;
  id: string;
  part?: {
    index: number;
    total: number;
  };
  stream?: {
    id: string;
    seq: number;
  };
};

export type NackFrame = {
  __xferkit: 1;
  v: typeof XFERKIT_VERSION;
  kind: "nack";
  channel: string;
  id: string;
  reason?: string;
  part?: {
    index: number;
    total: number;
  };
  stream?: {
    id: string;
    seq: number;
  };
};

export type ControlFrame = {
  __xferkit: 1;
  v: typeof XFERKIT_VERSION;
  kind: "control";
  channel: string;
  type: "handshake-init" | "handshake-reply" | "handshake-ack";
  handshakeId: string;
  curve?: "P-256" | "P-384" | "P-521";
  pub?: ArrayBuffer;
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

export function isControlFrame(frame: Frame): frame is ControlFrame {
  return frame.kind === "control";
}
