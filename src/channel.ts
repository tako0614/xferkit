import type {
  Xfer,
  XferEvent,
  XferHandler,
  XferHandshakeOptions,
  XferOptions,
  XferSendOptions,
  XferStats,
  XferStatus,
  XferStreamSendOptions,
  XferTarget,
} from "./types.js";
import {
  isAckFrame,
  isDataFrame,
  isFrame,
  isNackFrame,
  isControlFrame,
  type DataFrame,
  type ControlFrame,
  type Frame,
} from "./envelope.js";
import {
  applyCodecDecode,
  applyCodecEncode,
  createAuthTag,
  decodeBinaryPayload,
  encodeBinaryPayload,
  verifyAuthTag,
} from "./codec.js";
import { chunkBytes, mergeChunks } from "./chunk.js";
import { collectTransferables } from "./transfer.js";
import { postMessageTarget, supportsTransfer } from "./runtime.js";
import { parseWithTags, stringifyWithTags } from "./serializer.js";
import {
  base64ToBytes,
  bytesToBase64,
  clampMs,
  createDeferred,
  createId,
  nowMs,
} from "./util.js";
import {
  deriveSharedAesKey,
  exportKeyRaw,
  exportPublicKeyRaw,
  generateEcdhKeyPair,
  importKeyRaw,
  importPublicKeyRaw,
} from "./crypto.js";

type OutboundFrameSpec = {
  base: Omit<DataFrame, "payload">;
  mode: "structured" | "binary";
  payload: unknown | Uint8Array;
  transferList?: Transferable[];
  transferEnabled?: boolean;
  partIndex?: number;
};

type OutboundMessage = {
  id: string;
  seq?: number;
  ackMode: "message" | "chunk";
  frames: OutboundFrameSpec[];
  requireAck: boolean;
  retriesLeft: number;
  ackTimeoutMs: number;
  backoffMs: number;
  attempt: number;
  chunkStatus?: Array<"pending" | "sent" | "acked">;
  chunkWindow?: number;
  lastActivity: number;
  deferred: ReturnType<typeof createDeferred<void>>;
  timer?: ReturnType<typeof setTimeout>;
  signal?: AbortSignal;
  abortHandler?: () => void;
  persisted?: boolean;
};

type InboundMessage = {
  total: number;
  received: number;
  chunks: Array<Uint8Array | undefined>;
  format?: DataFrame["format"];
  binType?: DataFrame["binType"];
  codec?: DataFrame["codec"];
  auth?: DataFrame["auth"];
  authTag?: ArrayBuffer;
  iv?: ArrayBuffer;
  ackMode?: "message" | "chunk";
  seq?: number;
  updatedAt: number;
};

type OrderedMessage = {
  seq: number;
  payload: unknown;
  ack?: QueuedMessage["ack"];
  receivedAt: number;
};

type StreamEntry = {
  id: string;
  stream: ReadableStream<Uint8Array>;
  controller: ReadableStreamDefaultController<Uint8Array>;
  nextSeq: number;
  buffer: Map<number, { data: Uint8Array; ack?: { id: string; seq: number } }>;
  bufferBytes: number;
  meta?: unknown;
  doneSeq?: number;
  pendingDoneAck?: { id: string; seq: number };
  updatedAt: number;
};

type StreamChunkState = {
  id: string;
  seq: number;
  data: Uint8Array;
  frameBase: Omit<DataFrame, "payload">;
  transferEnabled: boolean;
  requireAck: boolean;
  retriesLeft: number;
  ackTimeoutMs: number;
  backoffMs: number;
  attempt: number;
  lastActivity: number;
  deferred: ReturnType<typeof createDeferred<void>>;
  timer?: ReturnType<typeof setTimeout>;
  abortHandler?: () => void;
};

type OutboundStreamState = {
  id: string;
  resumeKey?: string;
  offsetBytes: number;
  nextSeq: number;
  metaSent: boolean;
  meta?: unknown;
  chunkBytes?: number;
  requireAck: boolean;
  ackTimeoutMs: number;
  done: boolean;
  lastActivity: number;
};

type QueuedMessage = {
  payload: unknown;
  seq?: number;
  ack?: {
    id: string;
    part?: { index: number; total: number };
    ackMode?: "message" | "chunk";
    stream?: { id: string; seq: number };
  };
};

type HandshakeState = {
  id: string;
  curve: "P-256" | "P-384" | "P-521";
  keyPair: CryptoKeyPair;
  deferred: ReturnType<typeof createDeferred<CryptoKey>>;
  timer?: ReturnType<typeof setTimeout>;
};

type PersistedFrameBase = Omit<DataFrame, "payload" | "authTag" | "iv"> & {
  authTag?: string;
  iv?: string;
};

type PersistedFrame = {
  base: PersistedFrameBase;
  payload: string;
  transferEnabled?: boolean;
  partIndex?: number;
};

type PersistedMessage = {
  id: string;
  seq?: number;
  ackMode: "message" | "chunk";
  requireAck: boolean;
  retriesLeft: number;
  ackTimeoutMs: number;
  backoffMs: number;
  attempt: number;
  chunkStatus?: Array<"pending" | "sent" | "acked">;
  chunkWindow?: number;
  lastActivity: number;
  frames: PersistedFrame[];
};

type PersistedInbound = {
  total: number;
  received: number;
  chunks: Array<string | null>;
  format?: DataFrame["format"];
  binType?: DataFrame["binType"];
  codec?: DataFrame["codec"];
  auth?: DataFrame["auth"];
  authTag?: string;
  iv?: string;
  ackMode?: "message" | "chunk";
  seq?: number;
  updatedAt: number;
};

type PersistedStreamChunk = {
  id: string;
  seq: number;
  data: string;
  frameBase: PersistedFrameBase;
  transferEnabled: boolean;
  requireAck: boolean;
  retriesLeft: number;
  ackTimeoutMs: number;
  backoffMs: number;
  attempt: number;
  lastActivity: number;
};

type PersistedInboundStream = {
  id: string;
  nextSeq: number;
  buffer: Array<{ seq: number; data: string; ack?: 1 }>;
  meta?: string;
  doneSeq?: number;
  pendingDoneAck?: 1;
  updatedAt: number;
};

type PersistedOutboundStreamState = {
  id: string;
  resumeKey?: string;
  offsetBytes: number;
  nextSeq: number;
  metaSent: boolean;
  meta?: string;
  chunkBytes?: number;
  requireAck: boolean;
  ackTimeoutMs: number;
  done: boolean;
  lastActivity: number;
};

type PersistedSession = {
  version: 1;
  savedAt?: number;
  nextSeq?: number;
  outSeq?: number;
  sessionKey?: string;
  sessionKeyId?: string;
  recentReceived?: Array<[string, number]>;
  recentStreams?: Array<[string, number]>;
  outbound?: Record<string, PersistedMessage>;
  inbound?: Record<string, PersistedInbound>;
  outboundStreams?: PersistedStreamChunk[];
  inboundStreams?: Record<string, PersistedInboundStream>;
  outboundStreamStates?: Record<string, PersistedOutboundStreamState>;
};

const DEFAULT_RELIABILITY = {
  requireAck: true,
  ackTimeoutMs: 2500,
  maxRetries: 3,
  retryBackoffMs: 200,
  maxInFlight: 16,
  dedupeWindowMs: 60_000,
  inboundTimeoutMs: 60_000,
  ackMode: "chunk" as const,
  chunkWindowSize: 8,
  order: "strict" as const,
  orderTimeoutMs: 30_000,
};

export function createXfer(target: XferTarget, options: XferOptions = {}): Xfer {
  const channelId = options.channelId ?? "xfer";
  const reliability = { ...DEFAULT_RELIABILITY, ...options.reliability };
  const backpressure = {
    deferAck: false,
    maxQueue: 1024,
    maxStreamBufferBytes: 2 * 1024 * 1024,
    ...options.backpressure,
  };
  const session = options.session;
  const storage =
    session?.storage ??
    (typeof localStorage !== "undefined" ? localStorage : undefined);
  const sessionStorageKey = session ? `xferkit:${session.id}` : undefined;
  const sessionEnabled = Boolean(storage && sessionStorageKey);
  const sessionIndexKey = sessionStorageKey
    ? `${sessionStorageKey}:index`
    : undefined;
  const sessionChunkPrefix = sessionStorageKey
    ? `${sessionStorageKey}:part:`
    : undefined;
  const persistOutboundEnabled = Boolean(
    sessionEnabled && session?.persistOutbound
  );
  const persistInboundEnabled = Boolean(
    sessionEnabled && session?.persistInbound
  );
  const listeners: Record<XferEvent, Set<XferHandler>> = {
    message: new Set(),
    error: new Set(),
    status: new Set(),
    stream: new Set(),
  };
  const pending = new Map<string, OutboundMessage>();
  const inbound = new Map<string, InboundMessage>();
  const recentReceived = new Map<string, number>();
  const recentStreams = new Map<string, number>();
  const ordered = new Map<number, OrderedMessage>();
  const streams = new Map<string, StreamEntry>();
  const pendingStreamChunks = new Map<string, StreamChunkState>();
  const outboundStreamStates = new Map<string, OutboundStreamState>();
  const messageQueue: QueuedMessage[] = [];
  let handshakeState: HandshakeState | null = null;
  let sessionEncryptKey: CryptoKey | null = null;
  let sessionEncryptKeyId: string | undefined;
  let sessionSaveTimer: ReturnType<typeof setTimeout> | null = null;
  let sessionSaveInFlight = false;
  let sessionSaveQueued = false;
  let restoringSession = false;
  let adaptiveChunkBytes = options.chunk?.auto?.maxBytes ?? options.chunk?.maxBytes;
  let sessionReady: Promise<void> = Promise.resolve();
  const slotWaiters: Array<ReturnType<typeof createDeferred<void>>> = [];
  const messageStreamControllers = new Set<ReadableStreamDefaultController<unknown>>();
  const stats: XferStats = {
    sentMessages: 0,
    receivedMessages: 0,
    resentMessages: 0,
    droppedMessages: 0,
  };
  let nextSeq = 0;
  let orderWaitStartedAt = 0;
  let outSeq = 0;
  let inFlight = 0;
  let closed = false;

  const onMessage = (event: MessageEvent) => {
    void handleIncoming(event.data);
  };

  const onError = (event: MessageEvent) => {
    emit("error", event);
  };

  target.addEventListener("message", onMessage);
  target.addEventListener("messageerror", onError);

  const send = async (data: unknown, sendOptions?: XferSendOptions) => {
    if (closed) {
      throw new Error("xferkit channel is closed.");
    }
    if (sendOptions?.signal?.aborted) {
      throw new DOMException("Aborted", "AbortError");
    }
    await sessionReady;
    if (options.handshake?.auto) {
      await handshake(options.handshake);
    }
    const requireAck =
      sendOptions?.requireAck ?? reliability.requireAck ?? true;
    const ackTimeoutMs = clampMs(
      sendOptions?.timeoutMs ?? reliability.ackTimeoutMs ?? 2500,
      50
    );
    const message = await buildOutboundMessage(
      data,
      requireAck,
      ackTimeoutMs,
      sendOptions?.signal
    );
    await waitForSlot(requireAck, sendOptions?.signal);
    dispatchMessage(message);
    return message.deferred.promise;
  };

  const sendStream = async (
    stream: ReadableStream<Uint8Array>,
    sendOptions?: XferStreamSendOptions
  ) => {
    if (closed) {
      throw new Error("xferkit channel is closed.");
    }
    if (sendOptions?.signal?.aborted) {
      throw new DOMException("Aborted", "AbortError");
    }
    await sessionReady;
    if (options.handshake?.auto) {
      await handshake(options.handshake);
    }
    const requireAck =
      sendOptions?.requireAck ?? reliability.requireAck ?? true;
    const ackTimeoutMs = clampMs(
      sendOptions?.timeoutMs ?? reliability.ackTimeoutMs ?? 2500,
      50
    );
    await waitForSlot(requireAck, sendOptions?.signal);
    if (requireAck) {
      inFlight += 1;
    }
    try {
      await sendStreamInternal(stream, {
        requireAck,
        ackTimeoutMs,
        signal: sendOptions?.signal,
        chunkBytes: sendOptions?.chunkBytes ?? resolveAdaptiveChunkBytes(),
        meta: sendOptions?.meta,
        resumeKey: sendOptions?.resumeKey,
      });
    } finally {
      if (requireAck) {
        inFlight -= 1;
        releaseSlot();
      }
    }
  };

  const on = (event: XferEvent, handler: XferHandler) => {
    listeners[event].add(handler);
    return () => {
      listeners[event].delete(handler);
    };
  };

  const createMessageStream = () => {
    let controllerRef: ReadableStreamDefaultController<unknown> | null = null;
    return new ReadableStream<unknown>({
      start(controller) {
        controllerRef = controller;
        messageStreamControllers.add(controller);
      },
      pull() {
        pumpMessageQueue();
      },
      cancel() {
        if (controllerRef) {
          messageStreamControllers.delete(controllerRef);
        }
      },
    });
  };

  const close = () => {
    if (closed) {
      return;
    }
    requestSessionSave(true);
    closed = true;
    target.removeEventListener?.("message", onMessage);
    target.removeEventListener?.("messageerror", onError);
    if (handshakeState?.timer) {
      clearTimeout(handshakeState.timer);
    }
    handshakeState?.deferred.reject(new Error("xferkit channel closed."));
    handshakeState = null;
    if (sessionSaveTimer) {
      clearTimeout(sessionSaveTimer);
      sessionSaveTimer = null;
    }
    for (const message of pending.values()) {
      message.deferred.reject(new Error("xferkit channel closed."));
      if (message.timer) {
        clearTimeout(message.timer);
      }
    }
    pending.clear();
    inbound.clear();
    ordered.clear();
    recentStreams.clear();
    messageQueue.length = 0;
    streams.forEach((entry) => {
      try {
        entry.controller.close();
      } catch {
        // ignore
      }
    });
    streams.clear();
    pendingStreamChunks.forEach((chunk) => {
      if (chunk.timer) {
        clearTimeout(chunk.timer);
      }
      chunk.deferred.reject(new Error("xferkit channel closed."));
    });
    pendingStreamChunks.clear();
    listeners.message.clear();
    listeners.error.clear();
    listeners.status.clear();
    listeners.stream.clear();
    slotWaiters.splice(0).forEach((waiter) => waiter.reject());
    for (const controller of messageStreamControllers) {
      try {
        controller.close();
      } catch {
        // ignore
      }
    }
    messageStreamControllers.clear();
  };

  const getStats = () => ({ ...stats });

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

  const getCodecOptions = () => {
    const base = options.codec;
    if (!base?.encrypt || !sessionEncryptKey) {
      return base;
    }
    return {
      ...base,
      encrypt: {
        ...base.encrypt,
        key: sessionEncryptKey,
        keyId: sessionEncryptKeyId ?? base.encrypt.keyId,
      },
    };
  };

  const emitMessage = (
    payload: unknown,
    seq?: number,
    ack?: QueuedMessage["ack"]
  ) => {
    if (reliability.order === "strict" && typeof seq === "number") {
      queueOrderedMessage(seq, payload, ack);
      return;
    }
    enqueueMessage(payload, seq, ack);
  };

  const queueOrderedMessage = (
    seq: number,
    payload: unknown,
    ack?: QueuedMessage["ack"]
  ) => {
    if (!Number.isFinite(seq)) {
      enqueueMessage(payload, seq, ack);
      return;
    }
    ordered.set(seq, { seq, payload, ack, receivedAt: nowMs() });
    if (orderWaitStartedAt === 0 && seq !== nextSeq) {
      orderWaitStartedAt = nowMs();
    }
    drainOrdered();
  };

  const drainOrdered = () => {
    let advanced = false;
    while (ordered.has(nextSeq)) {
      const entry = ordered.get(nextSeq);
      if (!entry) {
        break;
      }
      ordered.delete(nextSeq);
      enqueueMessage(entry.payload, entry.seq, entry.ack);
      nextSeq += 1;
      advanced = true;
      orderWaitStartedAt = 0;
    }
    if (advanced) {
      requestSessionSave();
    }
    handleOrderTimeout();
  };

  const handleOrderTimeout = () => {
    const timeoutMs = reliability.orderTimeoutMs ?? 0;
    if (timeoutMs <= 0) {
      return;
    }
    if (ordered.size === 0) {
      return;
    }
    if (orderWaitStartedAt === 0) {
      orderWaitStartedAt = nowMs();
    }
    if (nowMs() - orderWaitStartedAt < timeoutMs) {
      return;
    }
    let nextAvailable = Number.POSITIVE_INFINITY;
    for (const key of ordered.keys()) {
      if (key > nextSeq && key < nextAvailable) {
        nextAvailable = key;
      }
    }
    if (!Number.isFinite(nextAvailable)) {
      return;
    }
    emit("error", new Error("xferkit order gap timeout"));
    nextSeq = nextAvailable;
    orderWaitStartedAt = 0;
    drainOrdered();
  };

  const canDeliverToStreams = () => {
    if (messageStreamControllers.size === 0) {
      return true;
    }
    for (const controller of messageStreamControllers) {
      const desired = controller.desiredSize ?? 1;
      if (desired <= 0) {
        return false;
      }
    }
    return true;
  };

  const enqueueMessage = (
    payload: unknown,
    _seq?: number,
    ack?: QueuedMessage["ack"]
  ) => {
    const shouldDefer = backpressure.deferAck || messageStreamControllers.size > 0;
    if (!shouldDefer) {
      deliverMessage(payload, ack);
      return;
    }
    if (messageQueue.length >= (backpressure.maxQueue ?? 1024)) {
      stats.droppedMessages += 1;
      if (ack) {
        sendNack(ack.id, "queue_overflow", ack.part, ack.stream);
      }
      return;
    }
    messageQueue.push({ payload, ack });
    pumpMessageQueue();
  };

  const pumpMessageQueue = () => {
    if (!canDeliverToStreams()) {
      return;
    }
    while (messageQueue.length > 0 && canDeliverToStreams()) {
      const entry = messageQueue.shift();
      if (!entry) {
        break;
      }
      deliverMessage(entry.payload, entry.ack);
    }
  };

  const deliverMessage = (payload: unknown, ack?: QueuedMessage["ack"]) => {
    emit("message", payload);
    if (messageStreamControllers.size > 0) {
      for (const controller of messageStreamControllers) {
        controller.enqueue(payload);
      }
    }
    if (ack && ack.ackMode !== "chunk") {
      sendAck(ack.id, ack.part, ack.stream);
    }
  };

  const waitForSlot = async (requireAck: boolean, signal?: AbortSignal) => {
    if (!requireAck) {
      return;
    }
    if (inFlight < (reliability.maxInFlight ?? 16)) {
      return;
    }
    if (signal?.aborted) {
      throw new DOMException("Aborted", "AbortError");
    }
    const waiter = createDeferred<void>();
    slotWaiters.push(waiter);
    const onAbort = () => {
      waiter.reject(new DOMException("Aborted", "AbortError"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      await waiter.promise;
    } finally {
      signal?.removeEventListener("abort", onAbort);
    }
  };

  const releaseSlot = () => {
    if (slotWaiters.length === 0) {
      return;
    }
    const waiter = slotWaiters.shift();
    waiter?.resolve();
  };

  const dispatchMessage = (message: OutboundMessage) => {
    if (closed) {
      message.deferred.reject(new Error("xferkit channel closed."));
      return;
    }
    if (message.requireAck) {
      inFlight += 1;
      pending.set(message.id, message);
      attachAbort(message);
      if (message.persisted) {
        requestSessionSave(true);
      }
    }
    message.lastActivity = nowMs();
    if (
      message.requireAck &&
      message.ackMode === "chunk" &&
      message.chunkStatus &&
      message.frames.length > 1
    ) {
      sendNextChunks(message);
    } else {
      for (const spec of message.frames) {
        const { frame, transferList } = buildWireFrame(spec);
        postMessageTarget(
          target,
          frame,
          transferList,
          options.targetOrigin
        );
      }
    }

    stats.sentMessages += 1;
    emitStatus({ type: "send", id: message.id, chunks: message.frames.length });

    if (!message.requireAck) {
      message.deferred.resolve();
      return;
    }

    scheduleAckTimeout(message);
  };

  const scheduleAckTimeout = (message: OutboundMessage) => {
    if (message.timer) {
      clearTimeout(message.timer);
    }
    message.timer = setTimeout(() => {
      handleAckTimeout(message.id);
    }, message.ackTimeoutMs);
  };

  const handleAckTimeout = (id: string) => {
    const message = pending.get(id);
    if (!message) {
      return;
    }
    if (message.signal?.aborted) {
      return;
    }
    if (message.ackMode === "chunk" && message.chunkStatus) {
      if (message.chunkStatus.every((status) => status === "acked")) {
        completeMessage(message);
        return;
      }
      if (message.retriesLeft <= 0) {
        pending.delete(id);
        detachAbort(message);
        inFlight -= 1;
        stats.droppedMessages += 1;
        emitStatus({ type: "drop", id, reason: "ack_timeout" });
        message.deferred.reject(new Error("xferkit ack timeout."));
        adjustAdaptiveChunk(message, false);
        if (message.persisted) {
          removePersistedMessage(message.id);
        }
        releaseSlot();
        return;
      }
      message.retriesLeft -= 1;
      message.attempt += 1;
      stats.resentMessages += 1;
      emitStatus({ type: "retry", id, attempt: message.attempt });
      const delay = message.backoffMs * Math.max(1, message.attempt);
      setTimeout(() => {
        resendPendingChunks(message);
      }, delay);
      scheduleAckTimeout(message);
      return;
    }
    if (message.retriesLeft <= 0) {
      pending.delete(id);
      detachAbort(message);
      inFlight -= 1;
      stats.droppedMessages += 1;
      emitStatus({ type: "drop", id, reason: "ack_timeout" });
      message.deferred.reject(new Error("xferkit ack timeout."));
      adjustAdaptiveChunk(message, false);
      if (message.persisted) {
        removePersistedMessage(message.id);
      }
      releaseSlot();
      return;
    }
    message.retriesLeft -= 1;
    message.attempt += 1;
    stats.resentMessages += 1;
    emitStatus({ type: "retry", id, attempt: message.attempt });
    const delay = message.backoffMs * Math.max(1, message.attempt);
    setTimeout(() => {
      resendMessage(message);
    }, delay);
  };

  const resendMessage = (message: OutboundMessage) => {
    if (closed) {
      message.deferred.reject(new Error("xferkit channel closed."));
      return;
    }
    for (const spec of message.frames) {
      const { frame, transferList } = buildWireFrame(spec);
      postMessageTarget(
        target,
        frame,
        transferList,
        options.targetOrigin
      );
    }
    scheduleAckTimeout(message);
  };

  const handleIncoming = async (data: unknown) => {
    if (!isFrame(data)) {
      emitMessage(data);
      return;
    }
    const frame = data as Frame;

    if (frame.channel !== channelId) {
      return;
    }

    if (isAckFrame(frame)) {
      if (frame.stream) {
        handleStreamAck(frame.stream.id, frame.stream.seq);
      } else if (frame.part) {
        handleChunkAck(frame.id, frame.part.index);
      } else {
        handleAck(frame.id);
      }
      return;
    }

    if (isNackFrame(frame)) {
      if (frame.stream) {
        handleStreamNack(frame.stream.id, frame.stream.seq, frame.reason);
      } else if (frame.part) {
        handleChunkNack(frame.id, frame.part.index, frame.reason);
      } else {
        handleNack(frame.id, frame.reason);
      }
      return;
    }

    if (isControlFrame(frame)) {
      await handleControlFrame(frame);
      return;
    }

    if (isDataFrame(frame)) {
      await handleDataFrame(frame);
    }
  };

  const completeMessage = (message: OutboundMessage) => {
    pending.delete(message.id);
    detachAbort(message);
    if (message.timer) {
      clearTimeout(message.timer);
    }
    inFlight -= 1;
    emitStatus({ type: "ack", id: message.id });
    message.deferred.resolve();
    releaseSlot();
    adjustAdaptiveChunk(message, message.attempt === 0);
    if (message.persisted) {
      removePersistedMessage(message.id);
    }
  };

  const handleAck = (id: string) => {
    const message = pending.get(id);
    if (!message) {
      return;
    }
    completeMessage(message);
  };

  const adjustAdaptiveChunk = (message: OutboundMessage, success: boolean) => {
    adjustAdaptiveChunkBytes(success, message.frames.length > 1);
  };

  const handleNack = (id: string, reason?: string) => {
    const message = pending.get(id);
    if (!message) {
      return;
    }
    if (message.timer) {
      clearTimeout(message.timer);
    }
    if (message.ackMode === "chunk" && message.chunkStatus) {
      if (message.retriesLeft <= 0) {
        pending.delete(id);
        detachAbort(message);
        inFlight -= 1;
        stats.droppedMessages += 1;
        emitStatus({ type: "drop", id, reason: reason ?? "nack" });
        message.deferred.reject(new Error(reason ?? "xferkit nack"));
        adjustAdaptiveChunk(message, false);
        if (message.persisted) {
          removePersistedMessage(message.id);
        }
        releaseSlot();
        return;
      }
      message.retriesLeft -= 1;
      message.attempt += 1;
      stats.resentMessages += 1;
      emitStatus({ type: "retry", id, attempt: message.attempt });
      resetChunks(message);
      resendPendingChunks(message);
      scheduleAckTimeout(message);
      return;
    }
    if (message.retriesLeft <= 0) {
      pending.delete(id);
      detachAbort(message);
      inFlight -= 1;
      stats.droppedMessages += 1;
      emitStatus({ type: "drop", id, reason: reason ?? "nack" });
      message.deferred.reject(new Error(reason ?? "xferkit nack"));
      adjustAdaptiveChunk(message, false);
      if (message.persisted) {
        removePersistedMessage(message.id);
      }
      releaseSlot();
      return;
    }
    message.retriesLeft -= 1;
    message.attempt += 1;
    stats.resentMessages += 1;
    emitStatus({ type: "retry", id, attempt: message.attempt });
    const delay = message.backoffMs * Math.max(1, message.attempt);
    setTimeout(() => {
      resendMessage(message);
    }, delay);
  };

  const handleChunkAck = (id: string, index: number) => {
    const message = pending.get(id);
    if (!message || !message.chunkStatus) {
      return;
    }
    if (message.chunkStatus[index] === "acked") {
      return;
    }
    message.chunkStatus[index] = "acked";
    if (message.persisted) {
      requestSessionSave();
    }
    message.lastActivity = nowMs();
    scheduleAckTimeout(message);
    sendNextChunks(message);
    if (message.chunkStatus.every((status) => status === "acked")) {
      completeMessage(message);
    }
  };

  const handleChunkNack = (id: string, index: number, reason?: string) => {
    const message = pending.get(id);
    if (!message || !message.chunkStatus) {
      return;
    }
    if (message.retriesLeft <= 0) {
      pending.delete(id);
      detachAbort(message);
      inFlight -= 1;
      stats.droppedMessages += 1;
      emitStatus({ type: "drop", id, reason: reason ?? "nack" });
      message.deferred.reject(new Error(reason ?? "xferkit nack"));
      adjustAdaptiveChunk(message, false);
      if (message.persisted) {
        removePersistedMessage(message.id);
      }
      releaseSlot();
      return;
    }
    message.retriesLeft -= 1;
    message.attempt += 1;
    stats.resentMessages += 1;
    emitStatus({ type: "retry", id, attempt: message.attempt });
    message.chunkStatus[index] = "pending";
    if (message.persisted) {
      requestSessionSave();
    }
    sendNextChunks(message);
    scheduleAckTimeout(message);
  };

  const attachAbort = (message: OutboundMessage) => {
    if (!message.signal || message.abortHandler) {
      return;
    }
    const onAbort = () => {
      if (!pending.has(message.id)) {
        return;
      }
      pending.delete(message.id);
      if (message.timer) {
        clearTimeout(message.timer);
      }
      inFlight -= 1;
      stats.droppedMessages += 1;
      emitStatus({ type: "drop", id: message.id, reason: "aborted" });
      message.deferred.reject(new DOMException("Aborted", "AbortError"));
      adjustAdaptiveChunk(message, false);
      if (message.persisted) {
        removePersistedMessage(message.id);
      }
      releaseSlot();
    };
    message.abortHandler = onAbort;
    message.signal.addEventListener("abort", onAbort, { once: true });
  };

  const detachAbort = (message: OutboundMessage) => {
    if (!message.signal || !message.abortHandler) {
      return;
    }
    message.signal.removeEventListener("abort", message.abortHandler);
    message.abortHandler = undefined;
  };

  const resetChunks = (message: OutboundMessage) => {
    if (!message.chunkStatus) {
      return;
    }
    for (let i = 0; i < message.chunkStatus.length; i += 1) {
      if (message.chunkStatus[i] !== "acked") {
        message.chunkStatus[i] = "pending";
      }
    }
    if (message.persisted) {
      requestSessionSave();
    }
  };

  const resendPendingChunks = (message: OutboundMessage) => {
    if (!message.chunkStatus) {
      return;
    }
    resetChunks(message);
    sendNextChunks(message);
  };

  const sendNextChunks = (message: OutboundMessage) => {
    if (!message.chunkStatus) {
      return;
    }
    const windowSize = message.chunkWindow ?? reliability.chunkWindowSize ?? 8;
    let inFlightChunks = 0;
    for (const status of message.chunkStatus) {
      if (status === "sent") {
        inFlightChunks += 1;
      }
    }
    let capacity = windowSize - inFlightChunks;
    if (capacity <= 0) {
      return;
    }
    for (const spec of message.frames) {
      if (capacity <= 0) {
        break;
      }
      const index =
        spec.partIndex ??
        spec.base.part?.index ??
        -1;
      if (index < 0 || !message.chunkStatus[index]) {
        continue;
      }
      if (message.chunkStatus[index] !== "pending") {
        continue;
      }
      const { frame, transferList } = buildWireFrame(spec);
      postMessageTarget(target, frame, transferList, options.targetOrigin);
      message.chunkStatus[index] = "sent";
      capacity -= 1;
      message.lastActivity = nowMs();
    }
  };

  const streamChunkKey = (id: string, seq: number) => `${id}:${seq}`;
  const getPendingStreamInfo = (streamId: string) => {
    let maxSeq = -1;
    let metaSent = false;
    for (const state of pendingStreamChunks.values()) {
      if (state.id !== streamId) {
        continue;
      }
      if (state.seq > maxSeq) {
        maxSeq = state.seq;
      }
      if (state.frameBase.stream?.meta !== undefined) {
        metaSent = true;
      }
    }
    return { maxSeq, metaSent };
  };

  const sendStreamInternal = async (
    stream: ReadableStream<Uint8Array>,
    sendOptions: {
      requireAck: boolean;
      ackTimeoutMs: number;
      signal?: AbortSignal;
      chunkBytes?: number;
      meta?: unknown;
      resumeKey?: string;
    },
    resumeState?: OutboundStreamState
  ) => {
    const reader = stream.getReader();
    const streamId = resumeState?.id ?? createId("stream");
    let seq = resumeState?.nextSeq ?? 0;
    let metaSent = resumeState?.metaSent ?? false;
    let offsetBytes = resumeState?.offsetBytes ?? 0;
    let streamState = resumeState;
    const resumeKey = sendOptions.resumeKey ?? resumeState?.resumeKey;
    if (persistOutboundEnabled && resumeKey) {
      if (!streamState) {
        streamState = {
          id: streamId,
          resumeKey,
          offsetBytes,
          nextSeq: seq,
          metaSent,
          meta: sendOptions.meta,
          chunkBytes: sendOptions.chunkBytes,
          requireAck: sendOptions.requireAck,
          ackTimeoutMs: sendOptions.ackTimeoutMs,
          done: false,
          lastActivity: nowMs(),
        };
        outboundStreamStates.set(streamId, streamState);
        requestSessionSave(true);
      } else {
        streamState.resumeKey = resumeKey;
      }
    }
    let splitOccurred = false;
    const windowSize = Math.max(1, reliability.chunkWindowSize ?? 8);
    const inFlight = new Set<Promise<void>>();
    const schedule = async (promise: Promise<void>) => {
      const guarded = promise.catch((err) => {
        throw err;
      });
      inFlight.add(guarded);
      guarded.finally(() => inFlight.delete(guarded));
      if (inFlight.size >= windowSize) {
        await Promise.race(inFlight);
      }
    };
    try {
      while (true) {
        if (sendOptions.signal?.aborted) {
          throw new DOMException("Aborted", "AbortError");
        }
        const { value, done } = await reader.read();
        if (done) {
          const meta = !metaSent ? sendOptions.meta : undefined;
          await schedule(
            sendStreamChunk(
              streamId,
              seq,
              new Uint8Array(0),
              true,
              meta,
              sendOptions
            )
          );
          if (streamState) {
            streamState.done = true;
            streamState.metaSent = true;
            streamState.nextSeq = seq + 1;
            streamState.lastActivity = nowMs();
            requestSessionSave(true);
          }
          break;
        }
        if (!value || value.byteLength === 0) {
          continue;
        }
        offsetBytes += value.byteLength;
        if (streamState) {
          streamState.offsetBytes = offsetBytes;
          streamState.lastActivity = nowMs();
          requestSessionSave();
        }
        const chunks = chunkBytes(value, sendOptions.chunkBytes);
        if (chunks.length > 1) {
          splitOccurred = true;
        }
        for (const chunk of chunks) {
          const meta = !metaSent ? sendOptions.meta : undefined;
          await schedule(
            sendStreamChunk(streamId, seq, chunk, false, meta, sendOptions)
          );
          metaSent = true;
          seq += 1;
          if (streamState) {
            streamState.metaSent = metaSent;
            streamState.nextSeq = seq;
            streamState.lastActivity = nowMs();
          }
        }
        if (streamState) {
          requestSessionSave();
        }
      }
      if (inFlight.size > 0) {
        await Promise.all(inFlight);
      }
      adjustAdaptiveChunkBytes(true, splitOccurred);
      if (streamState?.done) {
        outboundStreamStates.delete(streamId);
        requestSessionSave(true);
      }
    } catch (err) {
      adjustAdaptiveChunkBytes(false, splitOccurred);
      if (inFlight.size > 0) {
        await Promise.allSettled(inFlight);
      }
      throw err;
    } finally {
      reader.releaseLock();
    }
  };

  const sendStreamChunk = async (
    streamId: string,
    seq: number,
    data: Uint8Array,
    done: boolean,
    meta: unknown,
    sendOptions: {
      requireAck: boolean;
      ackTimeoutMs: number;
      signal?: AbortSignal;
    }
  ) => {
    if (sendOptions.signal?.aborted) {
      throw new DOMException("Aborted", "AbortError");
    }
    const codecOptions = getCodecOptions();
    const encoded = await applyCodecEncode(data, codecOptions);
    const auth = await createAuthTag(
      encoded.bytes,
      codecOptions?.auth,
      Boolean(encoded.codec?.encrypt)
    );
    const ivBuffer = encoded.iv ? toArrayBuffer(encoded.iv) : undefined;
    const frameBase: Omit<DataFrame, "payload"> = {
      __xferkit: 1,
      v: 1,
      kind: "data",
      channel: channelId,
      id: streamId,
      mode: "binary",
      ack: sendOptions.requireAck ? (1 as const) : undefined,
      ackMode: sendOptions.requireAck ? ("chunk" as const) : undefined,
      format: "bin",
      binType: "Uint8Array",
      codec: encoded.codec,
      auth: auth?.auth,
      authTag: auth ? toArrayBuffer(auth.tag) : undefined,
      iv: ivBuffer,
      stream: {
        id: streamId,
        seq,
        done: done ? 1 : undefined,
        meta,
      },
    };

    if (!sendOptions.requireAck) {
      const payload = encoded.bytes;
      const transferEnabled =
        options.transfer?.auto !== false && supportsTransfer(target);
      const payloadBuffer = transferEnabled
        ? payload.slice().buffer
        : toArrayBuffer(payload);
      const transferList = transferEnabled ? [payloadBuffer] : undefined;
      postMessageTarget(
        target,
        { ...frameBase, payload: payloadBuffer },
        transferList,
        options.targetOrigin
      );
      return;
    }

    const state: StreamChunkState = {
      id: streamId,
      seq,
      data: encoded.bytes,
      frameBase,
      transferEnabled:
        options.transfer?.auto !== false && supportsTransfer(target),
      requireAck: true,
      retriesLeft: reliability.maxRetries ?? 0,
      ackTimeoutMs: sendOptions.ackTimeoutMs,
      backoffMs: reliability.retryBackoffMs ?? 200,
      attempt: 0,
      lastActivity: nowMs(),
      deferred: createDeferred<void>(),
    };
    state.deferred.promise.catch(() => {});

    const key = streamChunkKey(streamId, seq);
    pendingStreamChunks.set(key, state);
    if (persistOutboundEnabled) {
      requestSessionSave(true);
    }
    scheduleStreamAckTimeout(state);
    postStreamChunk(state);
    const onAbort = () => {
      pendingStreamChunks.delete(key);
      if (state.timer) {
        clearTimeout(state.timer);
      }
      state.deferred.reject(new DOMException("Aborted", "AbortError"));
    };
    if (sendOptions.signal) {
      state.abortHandler = onAbort;
      sendOptions.signal.addEventListener("abort", onAbort, { once: true });
    }
    try {
      await state.deferred.promise;
    } finally {
      if (sendOptions.signal && state.abortHandler) {
        sendOptions.signal.removeEventListener("abort", state.abortHandler);
        state.abortHandler = undefined;
      }
    }
  };

  const postStreamChunk = (state: StreamChunkState) => {
    const payloadBuffer = state.transferEnabled
      ? state.data.slice().buffer
      : toArrayBuffer(state.data);
    const transferList = state.transferEnabled ? [payloadBuffer] : undefined;
    state.lastActivity = nowMs();
    postMessageTarget(
      target,
      { ...state.frameBase, payload: payloadBuffer },
      transferList,
      options.targetOrigin
    );
  };

  const scheduleStreamAckTimeout = (state: StreamChunkState) => {
    if (state.timer) {
      clearTimeout(state.timer);
    }
    state.timer = setTimeout(() => {
      handleStreamTimeout(state.id, state.seq);
    }, state.ackTimeoutMs);
  };

  const handleStreamTimeout = (id: string, seq: number) => {
    const key = streamChunkKey(id, seq);
    const state = pendingStreamChunks.get(key);
    if (!state) {
      return;
    }
    if (state.retriesLeft <= 0) {
      pendingStreamChunks.delete(key);
      if (state.timer) {
        clearTimeout(state.timer);
      }
      stats.droppedMessages += 1;
      state.deferred.reject(new Error("xferkit stream ack timeout"));
      if (persistOutboundEnabled) {
        requestSessionSave(true);
      }
      return;
    }
    state.retriesLeft -= 1;
    state.attempt += 1;
    stats.resentMessages += 1;
    const delay = state.backoffMs * Math.max(1, state.attempt);
    setTimeout(() => {
      postStreamChunk(state);
      scheduleStreamAckTimeout(state);
    }, delay);
  };

  const handleStreamAck = (id: string, seq: number) => {
    const key = streamChunkKey(id, seq);
    const state = pendingStreamChunks.get(key);
    if (!state) {
      return;
    }
    pendingStreamChunks.delete(key);
    if (state.timer) {
      clearTimeout(state.timer);
    }
    state.deferred.resolve();
    if (persistOutboundEnabled) {
      requestSessionSave(true);
    }
    finalizeOutboundStreamIfDone(id);
  };

  const handleStreamNack = (id: string, seq: number, reason?: string) => {
    const key = streamChunkKey(id, seq);
    const state = pendingStreamChunks.get(key);
    if (!state) {
      return;
    }
    if (state.timer) {
      clearTimeout(state.timer);
    }
    if (state.retriesLeft <= 0) {
      pendingStreamChunks.delete(key);
      stats.droppedMessages += 1;
      state.deferred.reject(new Error(reason ?? "xferkit stream nack"));
      if (persistOutboundEnabled) {
        requestSessionSave(true);
      }
      return;
    }
    state.retriesLeft -= 1;
    state.attempt += 1;
    stats.resentMessages += 1;
    const delay = state.backoffMs * Math.max(1, state.attempt);
    setTimeout(() => {
      postStreamChunk(state);
      scheduleStreamAckTimeout(state);
    }, delay);
  };

  const finalizeOutboundStreamIfDone = (id: string) => {
    const state = outboundStreamStates.get(id);
    if (!state || !state.done) {
      return;
    }
    for (const key of pendingStreamChunks.keys()) {
      if (key.startsWith(`${id}:`)) {
        return;
      }
    }
    outboundStreamStates.delete(id);
    requestSessionSave(true);
  };

  const canEnqueueStream = (entry: StreamEntry) => {
    const desired = entry.controller.desiredSize;
    if (desired === null) {
      return false;
    }
    if (typeof desired !== "number") {
      return true;
    }
    return desired > 0;
  };

  const handleStreamFrame = async (frame: DataFrame) => {
    if (!frame.stream) {
      return;
    }
    const payloadBytes = toBytes(frame.payload) ?? new Uint8Array(0);
    let decodedBytes = payloadBytes;
    try {
      await verifyAuthTag(
        payloadBytes,
        frame.auth,
        frame.authTag ? new Uint8Array(frame.authTag) : undefined,
        getCodecOptions()?.auth,
        Boolean(frame.codec?.encrypt)
      );
      decodedBytes = await applyCodecDecode(
        payloadBytes,
        frame.codec,
        getCodecOptions(),
        frame.iv ? new Uint8Array(frame.iv) : undefined
      );
    } catch (err) {
      stats.droppedMessages += 1;
      emit("error", err);
      if (frame.ack) {
        sendNack(
          frame.id,
          err instanceof Error ? err.message : "decode_error",
          undefined,
          { id: frame.stream.id, seq: frame.stream.seq }
        );
      }
      return;
    }

    const streamEntry = getStreamEntry(frame);
    if (!streamEntry) {
      return;
    }
    const shouldAck = Boolean(frame.ack && frame.ackMode === "chunk");
    const ackInfo = shouldAck
      ? { id: frame.stream.id, seq: frame.stream.seq }
      : undefined;
    const chunk = toUint8(decodedBytes);
    stats.receivedMessages += 1;

    if (frame.stream.seq < streamEntry.nextSeq || streamEntry.buffer.has(frame.stream.seq)) {
      if (shouldAck) {
        sendAck(frame.id, undefined, { id: frame.stream.id, seq: frame.stream.seq });
      }
      return;
    }

    if (frame.stream.done) {
      streamEntry.doneSeq = frame.stream.seq;
      if (shouldAck) {
        streamEntry.pendingDoneAck = ackInfo;
      }
    }

    if (frame.stream.seq === streamEntry.nextSeq && canEnqueueStream(streamEntry)) {
      if (chunk.byteLength > 0) {
        streamEntry.controller.enqueue(chunk);
      }
      streamEntry.nextSeq += 1;
      if (shouldAck) {
        sendAck(frame.id, undefined, { id: frame.stream.id, seq: frame.stream.seq });
        streamEntry.pendingDoneAck = undefined;
      }
      drainStreamBuffer(streamEntry);
    } else {
      const limit = backpressure.maxStreamBufferBytes ?? 2 * 1024 * 1024;
      if (streamEntry.bufferBytes + chunk.byteLength > limit) {
        stats.droppedMessages += 1;
        if (shouldAck) {
          sendNack(
            frame.id,
            "stream_buffer_overflow",
            undefined,
            { id: frame.stream.id, seq: frame.stream.seq }
          );
        }
        return;
      }
      streamEntry.buffer.set(frame.stream.seq, { data: chunk, ack: ackInfo });
      streamEntry.bufferBytes += chunk.byteLength;
    }

    streamEntry.updatedAt = nowMs();
    if (persistInboundEnabled) {
      requestSessionSave();
    }
    sweepInbound();
  };

  const createStreamEntry = (
    streamId: string,
    meta?: unknown
  ): StreamEntry | undefined => {
    if (recentStreams.has(streamId)) {
      return undefined;
    }
    let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
    let entryRef: StreamEntry | null = null;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controllerRef = controller;
      },
      pull() {
        if (entryRef) {
          drainStreamBuffer(entryRef);
        }
      },
      cancel() {
        if (!entryRef) {
          return;
        }
        streams.delete(entryRef.id);
        recentStreams.set(entryRef.id, nowMs());
        requestSessionSave();
      },
    });
    if (!controllerRef) {
      return undefined;
    }
    const entry: StreamEntry = {
      id: streamId,
      stream,
      controller: controllerRef,
      nextSeq: 0,
      buffer: new Map<number, { data: Uint8Array; ack?: { id: string; seq: number } }>(),
      bufferBytes: 0,
      meta,
      updatedAt: nowMs(),
    };
    entryRef = entry;
    streams.set(streamId, entry);
    emit("stream", { id: streamId, stream, meta: entry.meta });
    requestSessionSave();
    return entry;
  };

  const getStreamEntry = (frame: DataFrame): StreamEntry | null => {
    const streamId = frame.stream?.id;
    if (!streamId) {
      return null;
    }
    let entry = streams.get(streamId);
    if (!entry) {
      entry = createStreamEntry(streamId, frame.stream?.meta);
    } else if (entry.meta === undefined && frame.stream?.meta !== undefined) {
      entry.meta = frame.stream.meta;
    }
    return entry ?? null;
  };

  const drainStreamBuffer = (entry: StreamEntry) => {
    let drained = false;
    while (entry.buffer.has(entry.nextSeq) && canEnqueueStream(entry)) {
      const chunk = entry.buffer.get(entry.nextSeq);
      if (!chunk) {
        break;
      }
      entry.buffer.delete(entry.nextSeq);
      entry.bufferBytes = Math.max(0, entry.bufferBytes - chunk.data.byteLength);
      if (chunk.data.byteLength > 0) {
        entry.controller.enqueue(chunk.data);
      }
      const seq = entry.nextSeq;
      entry.nextSeq += 1;
      drained = true;
      if (chunk.ack) {
        sendAck(chunk.ack.id, undefined, { id: chunk.ack.id, seq: chunk.ack.seq });
        if (entry.doneSeq === seq) {
          entry.pendingDoneAck = undefined;
        }
      }
    }
    if (drained) {
      entry.updatedAt = nowMs();
      if (persistInboundEnabled) {
        requestSessionSave();
      }
    }
    tryCloseStream(entry);
  };

  const tryCloseStream = (entry: StreamEntry) => {
    if (entry.doneSeq === undefined) {
      return;
    }
    if (entry.nextSeq <= entry.doneSeq) {
      return;
    }
    if (entry.pendingDoneAck) {
      sendAck(entry.pendingDoneAck.id, undefined, {
        id: entry.pendingDoneAck.id,
        seq: entry.pendingDoneAck.seq,
      });
      entry.pendingDoneAck = undefined;
    }
    try {
      entry.controller.close();
    } catch {
      // ignore
    }
    streams.delete(entry.id);
    recentStreams.set(entry.id, nowMs());
    requestSessionSave();
  };

  const handleDataFrame = async (frame: DataFrame) => {
    if (frame.stream) {
      await handleStreamFrame(frame);
      return;
    }

    const duplicate = isDuplicate(frame.id);
    if (duplicate) {
      if (frame.ack) {
        sendAck(
          frame.id,
          frame.ackMode === "chunk" ? frame.part : undefined,
          frame.stream
        );
      }
      return;
    }

    try {
      if (frame.mode === "structured") {
        stats.receivedMessages += 1;
        markReceived(frame.id);
        emitMessage(frame.payload, frame.seq);
        if (frame.ack) {
          sendAck(frame.id);
        }
        return;
      }

      const payloadBytes = toBytes(frame.payload);
      if (!payloadBytes) {
        throw new Error("Invalid binary payload.");
      }
      await verifyAuthTag(
        payloadBytes,
        frame.auth,
        frame.authTag ? new Uint8Array(frame.authTag) : undefined,
        getCodecOptions()?.auth,
        Boolean(frame.codec?.encrypt)
      );

      if (!frame.part || frame.part.total <= 1) {
        const decoded = await decodePayload(frame, payloadBytes);
        stats.receivedMessages += 1;
        markReceived(frame.id);
        emitMessage(decoded, frame.seq);
        if (frame.ack) {
          sendAck(frame.id);
        }
        return;
      }

      const entry = getInboundEntry(frame);
      if (!entry) {
        throw new Error("Invalid inbound chunk metadata.");
      }
      if (!entry.chunks[frame.part.index]) {
        entry.chunks[frame.part.index] = payloadBytes;
        entry.received += 1;
      }
      entry.updatedAt = nowMs();
      if (persistInboundEnabled) {
        requestSessionSave();
      }

      if (frame.ack && frame.ackMode === "chunk") {
        sendAck(frame.id, frame.part);
      }

      if (entry.received === entry.total) {
        inbound.delete(frame.id);
        if (persistInboundEnabled) {
          requestSessionSave();
        }
        const merged = mergeChunks(entry.chunks.filter(Boolean) as Uint8Array[]);
        const decoded = await decodePayload(
          {
            ...frame,
            format: entry.format,
            binType: entry.binType,
            codec: entry.codec,
            iv: entry.iv,
            part: undefined,
          },
          merged
        );
        stats.receivedMessages += 1;
        markReceived(frame.id);
        emitMessage(decoded, entry.seq ?? frame.seq);
        if (frame.ack) {
          sendAck(frame.id);
        }
      }
    } catch (err) {
      stats.droppedMessages += 1;
      emit("error", err);
      if (frame.ack) {
        if (frame.part) {
          sendNack(
            frame.id,
            err instanceof Error ? err.message : "decode_error",
            frame.part
          );
        } else {
          sendNack(
            frame.id,
            err instanceof Error ? err.message : "decode_error"
          );
        }
      }
    } finally {
      sweepInbound();
    }
  };

  const decodePayload = async (frame: DataFrame, payloadBytes: Uint8Array) => {
    const decodedBytes = await applyCodecDecode(
      payloadBytes,
      frame.codec,
      getCodecOptions(),
      frame.iv ? new Uint8Array(frame.iv) : undefined
    );
    return decodeBinaryPayload(
      decodedBytes,
      frame.format ?? "json",
      frame.binType
    );
  };

  const getInboundEntry = (frame: DataFrame) => {
    if (!frame.part) {
      return null;
    }
    const total = frame.part.total;
    if (!Number.isFinite(total) || total <= 0) {
      return null;
    }
    const index = frame.part.index;
    if (!Number.isFinite(index) || index < 0 || index >= total) {
      return null;
    }
    let entry = inbound.get(frame.id);
    if (!entry) {
      entry = {
        total,
        received: 0,
        chunks: new Array<Uint8Array | undefined>(total),
        format: frame.format,
        binType: frame.binType,
        codec: frame.codec,
        auth: frame.auth,
        authTag: frame.authTag,
        iv: frame.iv,
        ackMode: frame.ackMode,
        seq: frame.seq,
        updatedAt: nowMs(),
      };
      inbound.set(frame.id, entry);
    } else {
      entry.format = entry.format ?? frame.format;
      entry.binType = entry.binType ?? frame.binType;
      entry.codec = entry.codec ?? frame.codec;
      entry.auth = entry.auth ?? frame.auth;
      entry.authTag = entry.authTag ?? frame.authTag;
      entry.iv = entry.iv ?? frame.iv;
      entry.ackMode = entry.ackMode ?? frame.ackMode;
      entry.seq = entry.seq ?? frame.seq;
    }
    return entry;
  };

  const markReceived = (id: string) => {
    recentReceived.set(id, nowMs());
    requestSessionSave();
  };

  const isDuplicate = (id: string) => {
    const ts = recentReceived.get(id);
    if (!ts) {
      return false;
    }
    return nowMs() - ts < (reliability.dedupeWindowMs ?? 60_000);
  };

  const sweepInbound = () => {
    const cutoff = nowMs() - (reliability.inboundTimeoutMs ?? 60_000);
    let didUpdate = false;
    for (const [id, entry] of inbound.entries()) {
      if (entry.updatedAt < cutoff) {
        inbound.delete(id);
        stats.droppedMessages += 1;
        didUpdate = true;
      }
    }
    for (const [id, entry] of streams.entries()) {
      if (entry.updatedAt < cutoff) {
        try {
          entry.controller.error(new Error("xferkit stream timeout"));
        } catch {
          // ignore
        }
        streams.delete(id);
        recentStreams.set(id, nowMs());
        stats.droppedMessages += 1;
        didUpdate = true;
      }
    }
    const dedupeCutoff = nowMs() - (reliability.dedupeWindowMs ?? 60_000);
    for (const [id, ts] of recentReceived.entries()) {
      if (ts < dedupeCutoff) {
        recentReceived.delete(id);
        didUpdate = true;
      }
    }
    for (const [id, ts] of recentStreams.entries()) {
      if (ts < dedupeCutoff) {
        recentStreams.delete(id);
        didUpdate = true;
      }
    }
    if (didUpdate) {
      requestSessionSave();
    }
  };

  const sendAck = (
    id: string,
    part?: { index: number; total: number },
    stream?: { id: string; seq: number }
  ) => {
    const frame: Frame = {
      __xferkit: 1,
      v: 1,
      kind: "ack",
      channel: channelId,
      id,
      part,
      stream,
    };
    postMessageTarget(target, frame, undefined, options.targetOrigin);
  };

  const sendNack = (
    id: string,
    reason?: string,
    part?: { index: number; total: number },
    stream?: { id: string; seq: number }
  ) => {
    const frame: Frame = {
      __xferkit: 1,
      v: 1,
      kind: "nack",
      channel: channelId,
      id,
      reason,
      part,
      stream,
    };
    postMessageTarget(target, frame, undefined, options.targetOrigin);
  };

  const emitStatus = (status: XferStatus) => {
    emit("status", status);
  };

  const resolveAdaptiveChunkBytes = () => {
    const auto = options.chunk?.auto;
    if (!auto) {
      return options.chunk?.maxBytes;
    }
    if (!adaptiveChunkBytes) {
      adaptiveChunkBytes =
        auto.maxBytes ?? options.chunk?.maxBytes ?? 256 * 1024;
    }
    return adaptiveChunkBytes;
  };

  const adjustAdaptiveChunkBytes = (success: boolean, shouldAdjust: boolean) => {
    const auto = options.chunk?.auto;
    if (!auto || !shouldAdjust) {
      return;
    }
    if (!adaptiveChunkBytes) {
      adaptiveChunkBytes =
        auto.maxBytes ?? options.chunk?.maxBytes ?? 256 * 1024;
    }
    const minBytes = auto.minBytes ?? 4096;
    const maxBytes =
      auto.maxBytes ?? options.chunk?.maxBytes ?? adaptiveChunkBytes;
    const increaseStep =
      auto.increaseStep ??
      Math.max(1024, Math.floor(adaptiveChunkBytes * 0.1));
    const decreaseFactor = auto.decreaseFactor ?? 0.5;
    if (success) {
      adaptiveChunkBytes = Math.min(maxBytes, adaptiveChunkBytes + increaseStep);
    } else {
      adaptiveChunkBytes = Math.max(
        minBytes,
        Math.floor(adaptiveChunkBytes * decreaseFactor)
      );
    }
  };

  const requestSessionSave = (force = false) => {
    if (!sessionEnabled) {
      return;
    }
    if (restoringSession) {
      return;
    }
    if (force) {
      if (sessionSaveTimer) {
        clearTimeout(sessionSaveTimer);
        sessionSaveTimer = null;
      }
      void saveSessionState(true);
      return;
    }
    if (sessionSaveTimer) {
      return;
    }
    sessionSaveTimer = setTimeout(() => {
      sessionSaveTimer = null;
      void saveSessionState(false);
    }, 50);
  };

  const serializeFrameBase = (
    base: Omit<DataFrame, "payload">
  ): PersistedFrameBase => {
    return {
      ...base,
      authTag: base.authTag
        ? bytesToBase64(new Uint8Array(base.authTag))
        : undefined,
      iv: base.iv ? bytesToBase64(new Uint8Array(base.iv)) : undefined,
    };
  };

  const restoreFrameBase = (base: PersistedFrameBase) => {
    return {
      ...base,
      authTag: base.authTag
        ? toArrayBuffer(base64ToBytes(base.authTag))
        : undefined,
      iv: base.iv ? toArrayBuffer(base64ToBytes(base.iv)) : undefined,
    };
  };

  const serializeFrameSpec = (spec: OutboundFrameSpec): PersistedFrame => {
    const base = serializeFrameBase(spec.base);
    if (spec.mode === "structured") {
      return {
        base,
        payload: stringifyWithTags(spec.payload),
        transferEnabled: spec.transferEnabled,
        partIndex: spec.partIndex,
      };
    }
    return {
      base,
      payload: bytesToBase64(spec.payload as Uint8Array),
      transferEnabled: spec.transferEnabled,
      partIndex: spec.partIndex,
    };
  };

  const restoreFrameSpec = (
    frame: PersistedFrame,
    transferEnabled: boolean
  ): OutboundFrameSpec => {
    const base = restoreFrameBase(frame.base);
    if (base.mode === "structured") {
      return {
        base,
        mode: "structured",
        payload: parseWithTags(frame.payload),
        transferEnabled,
        partIndex: frame.partIndex,
      };
    }
    return {
      base,
      mode: "binary",
      payload: base64ToBytes(frame.payload),
      transferEnabled,
      partIndex: frame.partIndex,
    };
  };

  const serializeOutboundMessage = (message: OutboundMessage): PersistedMessage => {
    return {
      id: message.id,
      seq: message.seq,
      ackMode: message.ackMode,
      requireAck: message.requireAck,
      retriesLeft: message.retriesLeft,
      ackTimeoutMs: message.ackTimeoutMs,
      backoffMs: message.backoffMs,
      attempt: message.attempt,
      chunkStatus: message.chunkStatus,
      chunkWindow: message.chunkWindow,
      lastActivity: message.lastActivity,
      frames: message.frames.map(serializeFrameSpec),
    };
  };

  const restoreOutboundMessage = (message: PersistedMessage): OutboundMessage => {
    const allowTransfer =
      options.transfer?.auto !== false && supportsTransfer(target);
    const frames = message.frames.map((frame) =>
      restoreFrameSpec(frame, allowTransfer)
    );
    return {
      id: message.id,
      seq: message.seq,
      ackMode: message.ackMode,
      frames,
      requireAck: message.requireAck,
      retriesLeft: message.retriesLeft,
      ackTimeoutMs: message.ackTimeoutMs,
      backoffMs: message.backoffMs,
      attempt: message.attempt,
      chunkStatus: message.chunkStatus,
      chunkWindow: message.chunkWindow ?? reliability.chunkWindowSize ?? 8,
      lastActivity: message.lastActivity,
      deferred: createDeferred<void>(),
      persisted: true,
    };
  };

  const serializeStreamChunk = (
    state: StreamChunkState
  ): PersistedStreamChunk => {
    return {
      id: state.id,
      seq: state.seq,
      data: bytesToBase64(state.data),
      frameBase: serializeFrameBase(state.frameBase),
      transferEnabled: state.transferEnabled,
      requireAck: state.requireAck,
      retriesLeft: state.retriesLeft,
      ackTimeoutMs: state.ackTimeoutMs,
      backoffMs: state.backoffMs,
      attempt: state.attempt,
      lastActivity: state.lastActivity,
    };
  };

  const restoreStreamChunk = (
    chunk: PersistedStreamChunk
  ): StreamChunkState => {
    const frameBase = restoreFrameBase(chunk.frameBase);
    return {
      id: chunk.id,
      seq: chunk.seq,
      data: base64ToBytes(chunk.data),
      frameBase,
      transferEnabled: chunk.transferEnabled,
      requireAck: chunk.requireAck,
      retriesLeft: chunk.retriesLeft,
      ackTimeoutMs: chunk.ackTimeoutMs,
      backoffMs: chunk.backoffMs,
      attempt: chunk.attempt,
      lastActivity: chunk.lastActivity ?? nowMs(),
      deferred: createDeferred<void>(),
    };
  };

  const serializeInboundStream = (entry: StreamEntry): PersistedInboundStream => {
    const buffer: Array<{ seq: number; data: string; ack?: 1 }> = [];
    for (const [seq, chunk] of entry.buffer.entries()) {
      buffer.push({
        seq,
        data: bytesToBase64(chunk.data),
        ack: chunk.ack ? 1 : undefined,
      });
    }
    return {
      id: entry.id,
      nextSeq: entry.nextSeq,
      buffer,
      meta: entry.meta !== undefined ? stringifyWithTags(entry.meta) : undefined,
      doneSeq: entry.doneSeq,
      pendingDoneAck: entry.pendingDoneAck ? 1 : undefined,
      updatedAt: entry.updatedAt,
    };
  };

  const serializeOutboundStreamState = (
    state: OutboundStreamState
  ): PersistedOutboundStreamState => {
    return {
      id: state.id,
      resumeKey: state.resumeKey,
      offsetBytes: state.offsetBytes,
      nextSeq: state.nextSeq,
      metaSent: state.metaSent,
      meta: state.meta !== undefined ? stringifyWithTags(state.meta) : undefined,
      chunkBytes: state.chunkBytes,
      requireAck: state.requireAck,
      ackTimeoutMs: state.ackTimeoutMs,
      done: state.done,
      lastActivity: state.lastActivity,
    };
  };

  const restoreOutboundStreamState = (
    state: PersistedOutboundStreamState
  ): OutboundStreamState => {
    return {
      id: state.id,
      resumeKey: state.resumeKey,
      offsetBytes: state.offsetBytes,
      nextSeq: state.nextSeq,
      metaSent: state.metaSent,
      meta: state.meta !== undefined ? parseWithTags(state.meta) : undefined,
      chunkBytes: state.chunkBytes,
      requireAck: state.requireAck,
      ackTimeoutMs: state.ackTimeoutMs,
      done: state.done,
      lastActivity: state.lastActivity,
    };
  };

  const persistOutboundMessage = (_message: OutboundMessage) => {
    if (!persistOutboundEnabled) {
      return;
    }
    requestSessionSave(true);
  };

  const removePersistedMessage = (_id: string) => {
    if (!persistOutboundEnabled) {
      return;
    }
    requestSessionSave(true);
  };

  const clearSessionStorage = () => {
    if (!storage || !sessionStorageKey) {
      return;
    }
    if (sessionIndexKey && sessionChunkPrefix) {
      const indexRaw = storage.getItem(sessionIndexKey);
      if (indexRaw) {
        try {
          const parsed = JSON.parse(indexRaw) as { count?: number };
          const count = parsed?.count ?? 0;
          if (Number.isFinite(count)) {
            for (let i = 0; i < count; i += 1) {
              storage.removeItem(`${sessionChunkPrefix}${i}`);
            }
          }
        } catch {
          // ignore malformed index
        }
        storage.removeItem(sessionIndexKey);
      }
    }
    storage.removeItem(sessionStorageKey);
  };

  const readSessionString = (): string | null => {
    if (!storage || !sessionStorageKey) {
      return null;
    }
    if (sessionIndexKey && sessionChunkPrefix) {
      const indexRaw = storage.getItem(sessionIndexKey);
      if (indexRaw) {
        try {
          const parsed = JSON.parse(indexRaw) as { count?: number };
          const count = parsed?.count ?? 0;
          if (!Number.isFinite(count) || count <= 0) {
            return null;
          }
          let combined = "";
          for (let i = 0; i < count; i += 1) {
            const part = storage.getItem(`${sessionChunkPrefix}${i}`);
            if (part === null) {
              return null;
            }
            combined += part;
          }
          return combined;
        } catch {
          return null;
        }
      }
    }
    return storage.getItem(sessionStorageKey);
  };

  const writeSessionString = (value: string) => {
    if (!storage || !sessionStorageKey) {
      return;
    }
    clearSessionStorage();
    const chunkSize = session?.chunkSize ?? 900_000;
    if (!sessionChunkPrefix || !sessionIndexKey || chunkSize <= 0) {
      storage.setItem(sessionStorageKey, value);
      return;
    }
    if (value.length <= chunkSize) {
      storage.setItem(sessionStorageKey, value);
      return;
    }
    const chunks: string[] = [];
    for (let i = 0; i < value.length; i += chunkSize) {
      chunks.push(value.slice(i, i + chunkSize));
    }
    for (let i = 0; i < chunks.length; i += 1) {
      storage.setItem(`${sessionChunkPrefix}${i}`, chunks[i]);
    }
    storage.setItem(sessionIndexKey, JSON.stringify({ count: chunks.length }));
  };

  const serializeSessionState = (
    state: PersistedSession
  ): string | null => {
    const maxBytes = session?.maxBytes ?? 4_000_000;
    let json = JSON.stringify(state);
    if (json.length <= maxBytes) {
      return json;
    }
    const drops: Array<{
      type: "inbound" | "outbound" | "inboundStream" | "outboundStreamState";
      id: string;
      ts: number;
    }> = [];
    if (state.inbound) {
      for (const [id, entry] of Object.entries(state.inbound)) {
        drops.push({ type: "inbound", id, ts: entry.updatedAt });
      }
    }
    if (state.outbound) {
      for (const [id, entry] of Object.entries(state.outbound)) {
        drops.push({ type: "outbound", id, ts: entry.lastActivity });
      }
    }
    if (state.inboundStreams) {
      for (const [id, entry] of Object.entries(state.inboundStreams)) {
        drops.push({ type: "inboundStream", id, ts: entry.updatedAt });
      }
    }
    if (state.outboundStreamStates) {
      for (const [id, entry] of Object.entries(state.outboundStreamStates)) {
        drops.push({ type: "outboundStreamState", id, ts: entry.lastActivity });
      }
    }
    drops.sort((a, b) => a.ts - b.ts);
    let trimmed = false;
    for (const entry of drops) {
      trimmed = true;
      if (entry.type === "inbound") {
        delete state.inbound?.[entry.id];
      } else if (entry.type === "outbound") {
        delete state.outbound?.[entry.id];
      } else if (entry.type === "outboundStreamState") {
        delete state.outboundStreamStates?.[entry.id];
      } else {
        delete state.inboundStreams?.[entry.id];
      }
      if (state.inbound && Object.keys(state.inbound).length === 0) {
        delete state.inbound;
      }
      if (state.outbound && Object.keys(state.outbound).length === 0) {
        delete state.outbound;
      }
      if (state.inboundStreams && Object.keys(state.inboundStreams).length === 0) {
        delete state.inboundStreams;
      }
      if (
        state.outboundStreamStates &&
        Object.keys(state.outboundStreamStates).length === 0
      ) {
        delete state.outboundStreamStates;
      }
      json = JSON.stringify(state);
      if (json.length <= maxBytes) {
        break;
      }
    }
    if (json.length > maxBytes) {
      if (state.outboundStreams) {
        delete state.outboundStreams;
        trimmed = true;
      }
      if (state.outboundStreamStates) {
        delete state.outboundStreamStates;
        trimmed = true;
      }
      if (state.recentReceived) {
        delete state.recentReceived;
        trimmed = true;
      }
      if (state.recentStreams) {
        delete state.recentStreams;
        trimmed = true;
      }
      if (state.sessionKey) {
        delete state.sessionKey;
        delete state.sessionKeyId;
        trimmed = true;
      }
      json = JSON.stringify(state);
    }
    if (trimmed) {
      emit(
        "error",
        new Error("xferkit session storage trimmed to fit size limits.")
      );
    }
    if (json.length > maxBytes) {
      return null;
    }
    return json;
  };

  const saveSessionState = async (force: boolean) => {
    if (!sessionEnabled || !sessionStorageKey || !storage) {
      return;
    }
    if (sessionSaveInFlight) {
      sessionSaveQueued = true;
      return;
    }
    sessionSaveInFlight = true;
    try {
      const state: PersistedSession = { version: 1, savedAt: nowMs() };
      if (reliability.order === "strict") {
        state.nextSeq = nextSeq;
      }
      state.outSeq = outSeq;
      if (recentReceived.size > 0) {
        state.recentReceived = Array.from(recentReceived.entries());
      }
      if (recentStreams.size > 0) {
        state.recentStreams = Array.from(recentStreams.entries());
      }
      if (persistOutboundEnabled) {
        const outboundState: Record<string, PersistedMessage> = {};
        for (const message of pending.values()) {
          if (!message.persisted) {
            continue;
          }
          outboundState[message.id] = serializeOutboundMessage(message);
        }
        if (Object.keys(outboundState).length > 0) {
          state.outbound = outboundState;
        }
      }
      if (persistInboundEnabled) {
        const inboundState: Record<string, PersistedInbound> = {};
        for (const [id, entry] of inbound.entries()) {
          inboundState[id] = {
            total: entry.total,
            received: entry.received,
            chunks: entry.chunks.map((chunk) =>
              chunk ? bytesToBase64(chunk) : null
            ),
            format: entry.format,
            binType: entry.binType,
            codec: entry.codec,
            auth: entry.auth,
            authTag: entry.authTag
              ? bytesToBase64(new Uint8Array(entry.authTag))
              : undefined,
            iv: entry.iv ? bytesToBase64(new Uint8Array(entry.iv)) : undefined,
            ackMode: entry.ackMode,
            seq: entry.seq,
            updatedAt: entry.updatedAt,
          };
        }
        if (Object.keys(inboundState).length > 0) {
          state.inbound = inboundState;
        }
      }
      if (persistOutboundEnabled && pendingStreamChunks.size > 0) {
        state.outboundStreams = Array.from(pendingStreamChunks.values()).map(
          serializeStreamChunk
        );
      }
      if (persistInboundEnabled && streams.size > 0) {
        const inboundStreams: Record<string, PersistedInboundStream> = {};
        for (const entry of streams.values()) {
          inboundStreams[entry.id] = serializeInboundStream(entry);
        }
        if (Object.keys(inboundStreams).length > 0) {
          state.inboundStreams = inboundStreams;
        }
      }
      if (persistOutboundEnabled && outboundStreamStates.size > 0) {
        const outboundStates: Record<string, PersistedOutboundStreamState> = {};
        for (const entry of outboundStreamStates.values()) {
          outboundStates[entry.id] = serializeOutboundStreamState(entry);
        }
        if (Object.keys(outboundStates).length > 0) {
          state.outboundStreamStates = outboundStates;
        }
      }
      if (sessionEncryptKey && (persistOutboundEnabled || persistInboundEnabled)) {
        try {
          const raw = await exportKeyRaw(sessionEncryptKey);
          state.sessionKey = bytesToBase64(new Uint8Array(raw));
          state.sessionKeyId = sessionEncryptKeyId;
        } catch {
          // ignore key export errors
        }
      }
      const hasState =
        Boolean(state.outbound) ||
        Boolean(state.inbound) ||
        Boolean(state.outboundStreams) ||
        Boolean(state.inboundStreams) ||
        Boolean(state.outboundStreamStates) ||
        Boolean(state.recentReceived?.length) ||
        Boolean(state.recentStreams?.length) ||
        Number.isFinite(state.nextSeq) ||
        Number.isFinite(state.outSeq) ||
        Boolean(state.sessionKey);
      if (!hasState) {
        clearSessionStorage();
        return;
      }
      const json = serializeSessionState(state);
      if (!json) {
        clearSessionStorage();
        return;
      }
      writeSessionString(json);
    } catch (err) {
      emit("error", err);
    } finally {
      sessionSaveInFlight = false;
      if (sessionSaveQueued) {
        sessionSaveQueued = false;
        void saveSessionState(false);
      }
    }
  };

  const loadSessionState = async (): Promise<PersistedSession | null> => {
    if (!sessionEnabled || !sessionStorageKey || !storage) {
      return null;
    }
    const raw = readSessionString();
    if (!raw) {
      return null;
    }
    let parsed: PersistedSession | null = null;
    try {
      parsed = JSON.parse(raw) as PersistedSession;
    } catch {
      clearSessionStorage();
      return null;
    }
    if (!parsed || parsed.version !== 1) {
      clearSessionStorage();
      return null;
    }
    if (
      session?.ttlMs &&
      parsed.savedAt &&
      nowMs() - parsed.savedAt > session.ttlMs
    ) {
      clearSessionStorage();
      return null;
    }
    if (parsed.sessionKey) {
      try {
        const rawKey = base64ToBytes(parsed.sessionKey);
        sessionEncryptKey = await importKeyRaw(toArrayBuffer(rawKey));
        sessionEncryptKeyId = parsed.sessionKeyId;
      } catch (err) {
        emit("error", err);
      }
    }
    return parsed;
  };

  const initializeSession = async () => {
    if (!sessionEnabled) {
      return;
    }
    restoringSession = true;
    let resumeRequests: OutboundStreamState[] = [];
    try {
      const state = await loadSessionState();
      if (!state) {
        return;
      }
      if (reliability.order === "strict" && Number.isFinite(state.nextSeq)) {
        nextSeq = state.nextSeq ?? nextSeq;
      }
      if (Number.isFinite(state.outSeq)) {
        outSeq = state.outSeq ?? outSeq;
      }
      if (state.recentReceived) {
        const cutoff = nowMs() - (reliability.dedupeWindowMs ?? 60_000);
        for (const [id, ts] of state.recentReceived) {
          if (ts >= cutoff) {
            recentReceived.set(id, ts);
          }
        }
      }
      if (state.recentStreams) {
        const cutoff = nowMs() - (reliability.dedupeWindowMs ?? 60_000);
        for (const [id, ts] of state.recentStreams) {
          if (ts >= cutoff) {
            recentStreams.set(id, ts);
          }
        }
      }
      if (persistInboundEnabled && state.inboundStreams) {
        for (const entry of Object.values(state.inboundStreams)) {
          if (
            nowMs() - entry.updatedAt >
            (reliability.inboundTimeoutMs ?? 60_000)
          ) {
            continue;
          }
          const meta =
            entry.meta !== undefined ? parseWithTags(entry.meta) : undefined;
          const streamEntry = createStreamEntry(entry.id, meta);
          if (!streamEntry) {
            continue;
          }
          streamEntry.nextSeq = entry.nextSeq;
          streamEntry.doneSeq = entry.doneSeq;
          streamEntry.pendingDoneAck =
            entry.pendingDoneAck && typeof entry.doneSeq === "number"
              ? { id: entry.id, seq: entry.doneSeq }
              : undefined;
          let bufferBytes = 0;
          for (const item of entry.buffer) {
            const data = base64ToBytes(item.data);
            bufferBytes += data.byteLength;
            streamEntry.buffer.set(item.seq, {
              data,
              ack: item.ack ? { id: entry.id, seq: item.seq } : undefined,
            });
          }
          streamEntry.bufferBytes = bufferBytes;
          streamEntry.updatedAt = entry.updatedAt;
          drainStreamBuffer(streamEntry);
        }
      }
      if (persistInboundEnabled && state.inbound) {
        for (const [id, entry] of Object.entries(state.inbound)) {
          if (
            nowMs() - entry.updatedAt >
            (reliability.inboundTimeoutMs ?? 60_000)
          ) {
            continue;
          }
          inbound.set(id, {
            total: entry.total,
            received: entry.received,
            chunks: entry.chunks.map((chunk) =>
              chunk ? base64ToBytes(chunk) : undefined
            ),
            format: entry.format,
            binType: entry.binType,
            codec: entry.codec,
            auth: entry.auth,
            authTag: entry.authTag
              ? toArrayBuffer(base64ToBytes(entry.authTag))
              : undefined,
            iv: entry.iv ? toArrayBuffer(base64ToBytes(entry.iv)) : undefined,
            ackMode: entry.ackMode,
            seq: entry.seq,
            updatedAt: entry.updatedAt,
          });
        }
      }
      if (persistOutboundEnabled && state.outboundStreams) {
        for (const entry of state.outboundStreams) {
          const stateEntry = restoreStreamChunk(entry);
          const key = streamChunkKey(stateEntry.id, stateEntry.seq);
          if (pendingStreamChunks.has(key)) {
            continue;
          }
          pendingStreamChunks.set(key, stateEntry);
          scheduleStreamAckTimeout(stateEntry);
          postStreamChunk(stateEntry);
          void stateEntry.deferred.promise.catch(() => {});
        }
      }
      resumeRequests = [];
      if (persistOutboundEnabled && state.outboundStreamStates) {
        for (const entry of Object.values(state.outboundStreamStates)) {
          const restored = restoreOutboundStreamState(entry);
          const pendingInfo = getPendingStreamInfo(restored.id);
          if (pendingInfo.maxSeq >= 0) {
            restored.nextSeq = Math.max(restored.nextSeq, pendingInfo.maxSeq + 1);
            if (pendingInfo.metaSent) {
              restored.metaSent = true;
            }
          }
          outboundStreamStates.set(restored.id, restored);
          if (!restored.done) {
            resumeRequests.push(restored);
          }
        }
      }
      const resumed: OutboundMessage[] = [];
      let maxSeq = outSeq;
      if (persistOutboundEnabled && state.outbound) {
        for (const entry of Object.values(state.outbound)) {
          const message = restoreOutboundMessage(entry);
          if (message.chunkStatus) {
            resetChunks(message);
          }
          if (typeof message.seq === "number") {
            maxSeq = Math.max(maxSeq, message.seq + 1);
          }
          resumed.push(message);
        }
      }
      if (!Number.isFinite(state.outSeq)) {
        outSeq = maxSeq;
      }
      if (resumed.length > 0) {
        for (const message of resumed) {
          emitStatus({ type: "resume", id: message.id });
          dispatchMessage(message);
        }
      }
    } finally {
      restoringSession = false;
    }
    if (resumeRequests.length > 0 && session?.streamResume) {
      const streamResume = session.streamResume;
      for (const entry of resumeRequests) {
        const resume = async () => {
          let reserved = false;
          try {
            const stream = await streamResume({
              key: entry.resumeKey ?? entry.id,
              offset: entry.offsetBytes,
              streamId: entry.id,
            });
            if (!stream) {
              throw new Error("Missing stream resume source.");
            }
            if (entry.requireAck) {
              await waitForSlot(true);
              inFlight += 1;
              reserved = true;
            }
            await sendStreamInternal(
              stream,
              {
                requireAck: entry.requireAck,
                ackTimeoutMs: entry.ackTimeoutMs,
                chunkBytes: entry.chunkBytes ?? resolveAdaptiveChunkBytes(),
                meta: entry.meta,
                resumeKey: entry.resumeKey,
              },
              entry
            );
          } catch (err) {
            emit("error", err);
          } finally {
            if (reserved) {
              inFlight -= 1;
              releaseSlot();
            }
          }
        };
        void resume();
      }
    }
  };

  const encodeHandshakeAuthPayload = (frame: ControlFrame): Uint8Array => {
    const pub = frame.pub ? bytesToBase64(new Uint8Array(frame.pub)) : "";
    const curve = frame.curve ?? "";
    const payload = `${frame.type}|${frame.handshakeId}|${curve}|${pub}`;
    return new TextEncoder().encode(payload);
  };

  const buildHandshakeAuth = async (frame: ControlFrame) => {
    const authOptions = getCodecOptions()?.auth;
    if (!authOptions) {
      return {};
    }
    const payload = encodeHandshakeAuthPayload(frame);
    const auth = await createAuthTag(payload, authOptions, false);
    return auth
      ? { auth: auth.auth, authTag: toArrayBuffer(auth.tag) }
      : {};
  };

  const verifyHandshakeAuth = async (frame: ControlFrame) => {
    const authOptions = getCodecOptions()?.auth;
    if (!authOptions) {
      return;
    }
    const enforced = { ...authOptions, required: true };
    const payload = encodeHandshakeAuthPayload(frame);
    await verifyAuthTag(
      payload,
      frame.auth,
      frame.authTag ? new Uint8Array(frame.authTag) : undefined,
      enforced,
      false
    );
  };

  const sendControlFrame = (frame: ControlFrame) => {
    postMessageTarget(target, frame, undefined, options.targetOrigin);
  };

  const handleControlFrame = async (frame: ControlFrame) => {
    try {
      await verifyHandshakeAuth(frame);
    } catch (err) {
      emit("error", err);
      return;
    }
    if (frame.type === "handshake-init") {
      if (!frame.pub) {
        return;
      }
      const curve = frame.curve ?? "P-256";
      try {
        const keyPair = await generateEcdhKeyPair(curve);
        const peerKey = await importPublicKeyRaw(frame.pub, curve);
        const shared = await deriveSharedAesKey(keyPair.privateKey, peerKey);
        sessionEncryptKey = shared;
        sessionEncryptKeyId = frame.handshakeId;
        const pub = await exportPublicKeyRaw(keyPair.publicKey);
        const auth = await buildHandshakeAuth({
          __xferkit: 1,
          v: 1,
          kind: "control",
          channel: channelId,
          type: "handshake-reply",
          handshakeId: frame.handshakeId,
          curve,
          pub,
        });
        sendControlFrame({
          __xferkit: 1,
          v: 1,
          kind: "control",
          channel: channelId,
          type: "handshake-reply",
          handshakeId: frame.handshakeId,
          curve,
          pub,
          ...auth,
        });
        if (handshakeState?.timer) {
          clearTimeout(handshakeState.timer);
        }
        handshakeState?.deferred.resolve(shared);
        handshakeState = null;
        requestSessionSave();
      } catch (err) {
        emit("error", err);
      }
      return;
    }
    if (frame.type === "handshake-reply") {
      if (!handshakeState || frame.handshakeId !== handshakeState.id || !frame.pub) {
        return;
      }
      try {
        const peerKey = await importPublicKeyRaw(frame.pub, handshakeState.curve);
        const shared = await deriveSharedAesKey(
          handshakeState.keyPair.privateKey,
          peerKey
        );
        sessionEncryptKey = shared;
        sessionEncryptKeyId = frame.handshakeId;
        const auth = await buildHandshakeAuth({
          __xferkit: 1,
          v: 1,
          kind: "control",
          channel: channelId,
          type: "handshake-ack",
          handshakeId: frame.handshakeId,
        });
        sendControlFrame({
          __xferkit: 1,
          v: 1,
          kind: "control",
          channel: channelId,
          type: "handshake-ack",
          handshakeId: frame.handshakeId,
          ...auth,
        });
        if (handshakeState.timer) {
          clearTimeout(handshakeState.timer);
        }
        handshakeState.deferred.resolve(shared);
        handshakeState = null;
        requestSessionSave();
      } catch (err) {
        emit("error", err);
      }
      return;
    }
    if (frame.type === "handshake-ack") {
      return;
    }
  };

  const handshake = async (
    handshakeOptions?: XferHandshakeOptions
  ): Promise<CryptoKey> => {
    await sessionReady;
    if (sessionEncryptKey) {
      return sessionEncryptKey;
    }
    if (handshakeState) {
      return handshakeState.deferred.promise;
    }
    const opts = { ...options.handshake, ...handshakeOptions };
    const curve = opts.curve ?? "P-256";
    const timeoutMs = clampMs(opts.timeoutMs ?? 5000, 100);
    const keyPair = await generateEcdhKeyPair(curve);
    const pub = await exportPublicKeyRaw(keyPair.publicKey);
    const id = createId("handshake");
    const deferred = createDeferred<CryptoKey>();
    handshakeState = { id, curve, keyPair, deferred };
    if (timeoutMs > 0) {
      handshakeState.timer = setTimeout(() => {
        if (!handshakeState || handshakeState.id !== id) {
          return;
        }
        handshakeState.deferred.reject(new Error("xferkit handshake timeout"));
        handshakeState = null;
      }, timeoutMs);
    }
    try {
      const auth = await buildHandshakeAuth({
        __xferkit: 1,
        v: 1,
        kind: "control",
        channel: channelId,
        type: "handshake-init",
        handshakeId: id,
        curve,
        pub,
      });
      sendControlFrame({
        __xferkit: 1,
        v: 1,
        kind: "control",
        channel: channelId,
        type: "handshake-init",
        handshakeId: id,
        curve,
        pub,
        ...auth,
      });
    } catch (err) {
      if (handshakeState?.timer) {
        clearTimeout(handshakeState.timer);
      }
      handshakeState?.deferred.reject(err);
      handshakeState = null;
      throw err;
    }
    return deferred.promise;
  };

  const buildOutboundMessage = async (
    data: unknown,
    requireAck: boolean,
    ackTimeoutMs: number,
    signal?: AbortSignal
  ): Promise<OutboundMessage> => {
    const codecOptions = getCodecOptions();
    const hasCodec = Boolean(codecOptions?.compress || codecOptions?.encrypt);
    const authEnabled = Boolean(codecOptions?.auth);
    const chunkLimit = resolveAdaptiveChunkBytes();
    const chunkEnabled = typeof chunkLimit === "number" && chunkLimit > 0;
    const forceBinary =
      hasCodec || chunkEnabled || authEnabled || persistOutboundEnabled;
    const id = createId("msg");
    const seq = outSeq;
    outSeq += 1;
    requestSessionSave();
    const retries = requireAck ? reliability.maxRetries ?? 0 : 0;
    const backoffMs = reliability.retryBackoffMs ?? 200;
    const allowTransfer = options.transfer?.auto !== false && supportsTransfer(target);
    const frameBase = {
      __xferkit: 1 as const,
      v: 1 as const,
      kind: "data" as const,
      channel: channelId,
      id,
      seq,
      ack: requireAck ? (1 as const) : undefined,
      ackMode: requireAck ? ("message" as const) : undefined,
    };

    if (!forceBinary) {
      const transferList =
        allowTransfer && retries === 0 ? collectTransferables(data) : undefined;
      return {
        id,
        seq,
        ackMode: "message",
        frames: [
          {
            base: { ...frameBase, mode: "structured" },
            mode: "structured",
            payload: data,
            transferList,
          },
        ],
        requireAck,
        retriesLeft: retries,
        ackTimeoutMs,
        backoffMs,
        attempt: 0,
        lastActivity: nowMs(),
        deferred: createDeferred<void>(),
        signal,
      };
    }

    const raw = encodeBinaryPayload(data);
    const encoded = await applyCodecEncode(raw.bytes, codecOptions);
    const chunks = chunkBytes(encoded.bytes, chunkEnabled ? chunkLimit : undefined);
    const ivBuffer = encoded.iv ? toArrayBuffer(encoded.iv) : undefined;
    const encrypted = Boolean(encoded.codec?.encrypt);
    const chunkAck =
      requireAck &&
      (reliability.ackMode ?? "message") === "chunk" &&
      chunks.length > 1;
    const frames: OutboundFrameSpec[] = [];
    for (let index = 0; index < chunks.length; index += 1) {
      const chunk = chunks[index];
      const auth = await createAuthTag(chunk, codecOptions?.auth, encrypted);
      frames.push({
        base: {
          ...frameBase,
          mode: "binary",
          ackMode: chunkAck ? ("chunk" as const) : ("message" as const),
          format: raw.format,
          binType: raw.binType,
          codec: encoded.codec,
          auth: auth?.auth,
          authTag: auth ? toArrayBuffer(auth.tag) : undefined,
          iv: ivBuffer,
          part:
            chunks.length > 1
              ? { index, total: chunks.length }
              : undefined,
        },
        mode: "binary",
        payload: chunk,
        transferEnabled: allowTransfer,
        partIndex: index,
      });
    }

    const message: OutboundMessage = {
      id,
      seq,
      ackMode: chunkAck ? "chunk" : "message",
      frames,
      requireAck,
      retriesLeft: retries,
      ackTimeoutMs,
      backoffMs,
      attempt: 0,
      chunkStatus: chunkAck
        ? new Array(chunks.length).fill("pending")
        : undefined,
      chunkWindow: reliability.chunkWindowSize ?? 8,
      lastActivity: nowMs(),
      deferred: createDeferred<void>(),
      signal,
    };
    if (persistOutboundEnabled && requireAck) {
      message.persisted = true;
      persistOutboundMessage(message);
    }
    return message;
  };

  const buildWireFrame = (
    spec: OutboundFrameSpec
  ): { frame: DataFrame; transferList?: Transferable[] } => {
    if (spec.mode === "structured") {
      return { frame: { ...spec.base, payload: spec.payload }, transferList: spec.transferList };
    }
    const payloadBytes = spec.payload as Uint8Array;
    const shouldTransfer = Boolean(spec.transferEnabled);
    const payloadBuffer = shouldTransfer
      ? payloadBytes.slice().buffer
      : toArrayBuffer(payloadBytes);
    return {
      frame: { ...spec.base, payload: payloadBuffer },
      transferList: shouldTransfer ? [payloadBuffer] : undefined,
    };
  };

  const toBytes = (payload: unknown): Uint8Array | null => {
    if (payload instanceof ArrayBuffer) {
      return new Uint8Array(payload);
    }
    if (
      typeof SharedArrayBuffer !== "undefined" &&
      payload instanceof SharedArrayBuffer
    ) {
      return new Uint8Array(payload);
    }
    if (ArrayBuffer.isView(payload)) {
      return new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
    }
    return null;
  };

  const toUint8 = (payload: unknown): Uint8Array => {
    if (payload instanceof Uint8Array) {
      return payload;
    }
    if (payload instanceof ArrayBuffer) {
      return new Uint8Array(payload);
    }
    if (
      typeof SharedArrayBuffer !== "undefined" &&
      payload instanceof SharedArrayBuffer
    ) {
      return new Uint8Array(payload);
    }
    if (ArrayBuffer.isView(payload)) {
      return new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
    }
    return new Uint8Array(0);
  };

  const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
    if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
      return bytes.buffer;
    }
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  };

  if (sessionEnabled) {
    sessionReady = initializeSession().catch((err) => {
      emit("error", err);
    });
  }
  if (options.handshake?.auto) {
    sessionReady
      .then(() => handshake(options.handshake))
      .catch((err) => emit("error", err));
  }

  return { send, sendStream, on, createMessageStream, handshake, close, getStats };
}
