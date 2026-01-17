import type {
  Xfer,
  XferEvent,
  XferHandler,
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
  type DataFrame,
  type Frame,
} from "./envelope.js";
import {
  applyCodecDecode,
  applyCodecEncode,
  decodeBinaryPayload,
  encodeBinaryPayload,
} from "./codec.js";
import { chunkBytes, mergeChunks } from "./chunk.js";
import { collectTransferables } from "./transfer.js";
import { postMessageTarget, supportsTransfer } from "./runtime.js";
import { clampMs, createDeferred, createId, nowMs } from "./util.js";

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
};

type InboundMessage = {
  total: number;
  received: number;
  chunks: Array<Uint8Array | undefined>;
  format?: DataFrame["format"];
  binType?: DataFrame["binType"];
  codec?: DataFrame["codec"];
  iv?: ArrayBuffer;
  ackMode?: "message" | "chunk";
  seq?: number;
  updatedAt: number;
};

type OrderedMessage = {
  seq: number;
  payload: unknown;
  receivedAt: number;
};

type StreamEntry = {
  id: string;
  stream: ReadableStream<Uint8Array>;
  controller: ReadableStreamDefaultController<Uint8Array>;
  nextSeq: number;
  buffer: Map<number, Uint8Array>;
  meta?: unknown;
  doneSeq?: number;
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
  deferred: ReturnType<typeof createDeferred<void>>;
  timer?: ReturnType<typeof setTimeout>;
  abortHandler?: () => void;
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
        chunkBytes: sendOptions?.chunkBytes ?? options.chunk?.maxBytes,
        meta: sendOptions?.meta,
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
    closed = true;
    target.removeEventListener?.("message", onMessage);
    target.removeEventListener?.("messageerror", onError);
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

  const emitMessage = (payload: unknown, seq?: number) => {
    if (reliability.order === "strict" && typeof seq === "number") {
      queueOrderedMessage(seq, payload);
      return;
    }
    emit("message", payload);
    for (const controller of messageStreamControllers) {
      controller.enqueue(payload);
    }
  };

  const queueOrderedMessage = (seq: number, payload: unknown) => {
    if (!Number.isFinite(seq)) {
      emitMessage(payload);
      return;
    }
    ordered.set(seq, { seq, payload, receivedAt: nowMs() });
    if (orderWaitStartedAt === 0 && seq !== nextSeq) {
      orderWaitStartedAt = nowMs();
    }
    drainOrdered();
  };

  const drainOrdered = () => {
    while (ordered.has(nextSeq)) {
      const entry = ordered.get(nextSeq);
      if (!entry) {
        break;
      }
      ordered.delete(nextSeq);
      emit("message", entry.payload);
      for (const controller of messageStreamControllers) {
        controller.enqueue(entry.payload);
      }
      nextSeq += 1;
      orderWaitStartedAt = 0;
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
  };

  const handleAck = (id: string) => {
    const message = pending.get(id);
    if (!message) {
      return;
    }
    completeMessage(message);
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
      releaseSlot();
      return;
    }
    message.retriesLeft -= 1;
    message.attempt += 1;
    stats.resentMessages += 1;
    emitStatus({ type: "retry", id, attempt: message.attempt });
    message.chunkStatus[index] = "pending";
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

  const sendStreamInternal = async (
    stream: ReadableStream<Uint8Array>,
    sendOptions: {
      requireAck: boolean;
      ackTimeoutMs: number;
      signal?: AbortSignal;
      chunkBytes?: number;
      meta?: unknown;
    }
  ) => {
    const reader = stream.getReader();
    const streamId = createId("stream");
    let seq = 0;
    let metaSent = false;
    try {
      while (true) {
        if (sendOptions.signal?.aborted) {
          throw new DOMException("Aborted", "AbortError");
        }
        const { value, done } = await reader.read();
        if (done) {
          const meta = !metaSent ? sendOptions.meta : undefined;
          await sendStreamChunk(
            streamId,
            seq,
            new Uint8Array(0),
            true,
            meta,
            sendOptions
          );
          break;
        }
        if (!value || value.byteLength === 0) {
          continue;
        }
        const chunks = chunkBytes(value, sendOptions.chunkBytes);
        for (const chunk of chunks) {
          const meta = !metaSent ? sendOptions.meta : undefined;
          await sendStreamChunk(
            streamId,
            seq,
            chunk,
            false,
            meta,
            sendOptions
          );
          metaSent = true;
          seq += 1;
        }
      }
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
    const encoded = await applyCodecEncode(data, options.codec);
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
      deferred: createDeferred<void>(),
    };

    const key = streamChunkKey(streamId, seq);
    pendingStreamChunks.set(key, state);
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

  const handleStreamFrame = async (frame: DataFrame) => {
    if (!frame.stream) {
      return;
    }
    const payloadBytes = toBytes(frame.payload) ?? new Uint8Array(0);
    let decodedBytes = payloadBytes;
    try {
      decodedBytes = await applyCodecDecode(
        payloadBytes,
        frame.codec,
        options.codec,
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

    if (frame.ack && frame.ackMode === "chunk") {
      sendAck(frame.id, undefined, { id: frame.stream.id, seq: frame.stream.seq });
    }

    const chunk = toUint8(decodedBytes);
    stats.receivedMessages += 1;
    if (frame.stream.done && chunk.byteLength === 0) {
      streamEntry.doneSeq = frame.stream.seq;
      streamEntry.updatedAt = nowMs();
      if (streamEntry.doneSeq !== undefined && streamEntry.nextSeq >= streamEntry.doneSeq) {
        streamEntry.controller.close();
        streams.delete(frame.stream.id);
        recentStreams.set(frame.stream.id, nowMs());
      }
      sweepInbound();
      return;
    }
    if (frame.stream.seq < streamEntry.nextSeq || streamEntry.buffer.has(frame.stream.seq)) {
      return;
    }
    if (frame.stream.seq === streamEntry.nextSeq) {
      streamEntry.controller.enqueue(chunk);
      streamEntry.nextSeq += 1;
      drainStreamBuffer(streamEntry);
    } else {
      streamEntry.buffer.set(frame.stream.seq, chunk);
    }
    if (frame.stream.done) {
      streamEntry.doneSeq = frame.stream.seq;
    }
    streamEntry.updatedAt = nowMs();
    if (streamEntry.doneSeq !== undefined && streamEntry.nextSeq >= streamEntry.doneSeq) {
      streamEntry.controller.close();
      streams.delete(frame.stream.id);
      recentStreams.set(frame.stream.id, nowMs());
    }
    sweepInbound();
  };

  const getStreamEntry = (frame: DataFrame): StreamEntry | null => {
    const streamId = frame.stream?.id;
    if (!streamId) {
      return null;
    }
    if (recentStreams.has(streamId)) {
      return null;
    }
    let entry = streams.get(streamId);
    if (!entry) {
      let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controllerRef = controller;
        },
      });
      if (!controllerRef) {
        return null;
      }
      entry = {
        id: streamId,
        stream,
        controller: controllerRef,
        nextSeq: 0,
        buffer: new Map<number, Uint8Array>(),
        meta: frame.stream?.meta,
        updatedAt: nowMs(),
      };
      streams.set(streamId, entry);
      emit("stream", { id: streamId, stream, meta: entry.meta });
    } else if (entry.meta === undefined && frame.stream?.meta !== undefined) {
      entry.meta = frame.stream.meta;
    }
    return entry;
  };

  const drainStreamBuffer = (entry: StreamEntry) => {
    while (entry.buffer.has(entry.nextSeq)) {
      const chunk = entry.buffer.get(entry.nextSeq);
      if (!chunk) {
        break;
      }
      entry.buffer.delete(entry.nextSeq);
      entry.controller.enqueue(chunk);
      entry.nextSeq += 1;
    }
    if (entry.doneSeq !== undefined && entry.nextSeq >= entry.doneSeq) {
      entry.controller.close();
      streams.delete(entry.id);
      recentStreams.set(entry.id, nowMs());
    }
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

      if (frame.ack && frame.ackMode === "chunk") {
        sendAck(frame.id, frame.part);
      }

      if (entry.received === entry.total) {
        inbound.delete(frame.id);
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
      options.codec,
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
      entry.iv = entry.iv ?? frame.iv;
      entry.ackMode = entry.ackMode ?? frame.ackMode;
      entry.seq = entry.seq ?? frame.seq;
    }
    return entry;
  };

  const markReceived = (id: string) => {
    recentReceived.set(id, nowMs());
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
    for (const [id, entry] of inbound.entries()) {
      if (entry.updatedAt < cutoff) {
        inbound.delete(id);
        stats.droppedMessages += 1;
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
      }
    }
    const dedupeCutoff = nowMs() - (reliability.dedupeWindowMs ?? 60_000);
    for (const [id, ts] of recentReceived.entries()) {
      if (ts < dedupeCutoff) {
        recentReceived.delete(id);
      }
    }
    for (const [id, ts] of recentStreams.entries()) {
      if (ts < dedupeCutoff) {
        recentStreams.delete(id);
      }
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

  const buildOutboundMessage = async (
    data: unknown,
    requireAck: boolean,
    ackTimeoutMs: number,
    signal?: AbortSignal
  ): Promise<OutboundMessage> => {
    const hasCodec = Boolean(options.codec?.compress || options.codec?.encrypt);
    const chunkLimit = options.chunk?.maxBytes;
    const chunkEnabled = typeof chunkLimit === "number" && chunkLimit > 0;
    const forceBinary = hasCodec || chunkEnabled;
    const id = createId("msg");
    const seq = outSeq;
    outSeq += 1;
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
    const encoded = await applyCodecEncode(raw.bytes, options.codec);
    const chunks = chunkBytes(encoded.bytes, chunkEnabled ? chunkLimit : undefined);
    const ivBuffer = encoded.iv ? toArrayBuffer(encoded.iv) : undefined;
    const chunkAck =
      requireAck &&
      (reliability.ackMode ?? "message") === "chunk" &&
      chunks.length > 1;
    const frames: OutboundFrameSpec[] = chunks.map((chunk, index) => ({
      base: {
        ...frameBase,
        mode: "binary",
        ackMode: chunkAck ? ("chunk" as const) : ("message" as const),
        format: raw.format,
        binType: raw.binType,
        codec: encoded.codec,
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
    }));

    return {
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

  return { send, sendStream, on, createMessageStream, close, getStats };
}
