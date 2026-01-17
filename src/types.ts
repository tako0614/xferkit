export type CompressAlgo = "gzip" | "deflate" | "brotli";
export type EncryptAlgo = "aes-gcm";

export interface XferCompressOptions {
  algo: CompressAlgo;
  level?: number;
  fallback?: "error" | "skip";
}

export type AuthAlgo = "hmac-sha-256";

export interface XferAuthOptions {
  algo?: AuthAlgo;
  key: CryptoKey | XferKeyring;
  keyId?: string;
  required?: boolean;
  skipIfEncrypted?: boolean;
}

export interface XferKeyring {
  current: CryptoKey;
  currentId?: string;
  keys?: Record<string, CryptoKey>;
}

export interface XferEncryptOptions {
  algo: EncryptAlgo;
  key: CryptoKey | XferKeyring;
  keyId?: string;
  ivLength?: number;
}

export interface XferCodecOptions {
  compress?: XferCompressOptions;
  encrypt?: XferEncryptOptions;
  auth?: XferAuthOptions;
}

export interface XferTransferOptions {
  auto?: boolean;
}

export interface XferAdaptiveChunkOptions {
  minBytes?: number;
  maxBytes?: number;
  increaseStep?: number;
  decreaseFactor?: number;
}

export interface XferChunkOptions {
  maxBytes?: number;
  auto?: XferAdaptiveChunkOptions;
}

export interface XferStreamSendOptions {
  chunkBytes?: number;
  requireAck?: boolean;
  timeoutMs?: number;
  signal?: AbortSignal;
  meta?: unknown;
}

export interface XferBackpressureOptions {
  deferAck?: boolean;
  maxQueue?: number;
  maxStreamBufferBytes?: number;
}

export interface XferHandshakeOptions {
  auto?: boolean;
  timeoutMs?: number;
  curve?: "P-256" | "P-384" | "P-521";
}

export interface XferSessionOptions {
  id: string;
  storage?: Storage;
  persistOutbound?: boolean;
  persistInbound?: boolean;
  ttlMs?: number;
}

export interface XferReliabilityOptions {
  requireAck?: boolean;
  ackTimeoutMs?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  maxInFlight?: number;
  dedupeWindowMs?: number;
  inboundTimeoutMs?: number;
  ackMode?: "message" | "chunk";
  chunkWindowSize?: number;
  order?: "strict" | "none";
  orderTimeoutMs?: number;
}

export interface XferOptions {
  channelId?: string;
  codec?: XferCodecOptions;
  transfer?: XferTransferOptions;
  chunk?: XferChunkOptions;
  reliability?: XferReliabilityOptions;
  targetOrigin?: string;
  backpressure?: XferBackpressureOptions;
  handshake?: XferHandshakeOptions;
  session?: XferSessionOptions;
}

export interface XferSendOptions {
  requireAck?: boolean;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export type XferEvent = "message" | "error" | "status" | "stream";
export type XferHandler = (payload: unknown) => void;

export type XferStatus =
  | { type: "send"; id: string; chunks: number }
  | { type: "ack"; id: string }
  | { type: "retry"; id: string; attempt: number }
  | { type: "drop"; id: string; reason: string }
  | { type: "resume"; id: string };

export interface XferStats {
  sentMessages: number;
  receivedMessages: number;
  resentMessages: number;
  droppedMessages: number;
}

export interface XferStreamInfo {
  id: string;
  stream: ReadableStream<Uint8Array>;
  meta?: unknown;
}

export interface Xfer {
  send(data: unknown, options?: XferSendOptions): Promise<void>;
  sendStream(
    stream: ReadableStream<Uint8Array>,
    options?: XferStreamSendOptions
  ): Promise<void>;
  on(event: XferEvent, handler: XferHandler): () => void;
  createMessageStream(): ReadableStream<unknown>;
  handshake(options?: XferHandshakeOptions): Promise<CryptoKey>;
  close(): void;
  getStats(): XferStats;
}

export type XferTarget = {
  postMessage: (...args: unknown[]) => void;
  addEventListener: (
    type: "message" | "messageerror",
    listener: (event: MessageEvent) => void
  ) => void;
  removeEventListener?: (
    type: "message" | "messageerror",
    listener: (event: MessageEvent) => void
  ) => void;
};
