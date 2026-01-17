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

export interface XferChunkOptions {
  maxBytes?: number;
}

export interface XferReliabilityOptions {
  requireAck?: boolean;
  ackTimeoutMs?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  maxInFlight?: number;
  dedupeWindowMs?: number;
  inboundTimeoutMs?: number;
}

export interface XferOptions {
  channelId?: string;
  codec?: XferCodecOptions;
  transfer?: XferTransferOptions;
  chunk?: XferChunkOptions;
  reliability?: XferReliabilityOptions;
  targetOrigin?: string;
}

export interface XferSendOptions {
  requireAck?: boolean;
  timeoutMs?: number;
}

export type XferEvent = "message" | "error" | "status";
export type XferHandler = (payload: unknown) => void;

export type XferStatus =
  | { type: "send"; id: string; chunks: number }
  | { type: "ack"; id: string }
  | { type: "retry"; id: string; attempt: number }
  | { type: "drop"; id: string; reason: string };

export interface XferStats {
  sentMessages: number;
  receivedMessages: number;
  resentMessages: number;
  droppedMessages: number;
}

export interface Xfer {
  send(data: unknown, options?: XferSendOptions): Promise<void>;
  on(event: XferEvent, handler: XferHandler): () => void;
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
