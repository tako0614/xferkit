import type {
  Xfer,
  XferEvent,
  XferHandler,
  XferOptions,
  XferSendOptions,
  XferStats,
  XferStatus,
  XferTarget,
} from "./types";
import {
  isAckFrame,
  isDataFrame,
  isFrame,
  isNackFrame,
  type DataFrame,
  type Frame,
} from "./envelope";
import {
  applyCodecDecode,
  applyCodecEncode,
  decodeBinaryPayload,
  encodeBinaryPayload,
} from "./codec";
import { chunkBytes, mergeChunks } from "./chunk";
import { collectTransferables } from "./transfer";
import { postMessageTarget, supportsTransfer } from "./runtime";
import { clampMs, createDeferred, createId, nowMs } from "./util";

type OutboundFrameSpec = {
  base: Omit<DataFrame, "payload">;
  mode: "structured" | "binary";
  payload: unknown | Uint8Array;
  transferList?: Transferable[];
  transferEnabled?: boolean;
};

type OutboundMessage = {
  id: string;
  frames: OutboundFrameSpec[];
  requireAck: boolean;
  retriesLeft: number;
  ackTimeoutMs: number;
  backoffMs: number;
  attempt: number;
  deferred: ReturnType<typeof createDeferred<void>>;
  timer?: ReturnType<typeof setTimeout>;
};

type InboundMessage = {
  total: number;
  received: number;
  chunks: Array<Uint8Array | undefined>;
  format?: DataFrame["format"];
  binType?: DataFrame["binType"];
  codec?: DataFrame["codec"];
  iv?: ArrayBuffer;
  updatedAt: number;
};

const DEFAULT_RELIABILITY = {
  requireAck: true,
  ackTimeoutMs: 2500,
  maxRetries: 3,
  retryBackoffMs: 200,
  maxInFlight: 16,
  dedupeWindowMs: 60_000,
  inboundTimeoutMs: 60_000,
};

export function createXfer(target: XferTarget, options: XferOptions = {}): Xfer {
  const channelId = options.channelId ?? createId("xfer");
  const reliability = { ...DEFAULT_RELIABILITY, ...options.reliability };
  const listeners: Record<XferEvent, Set<XferHandler>> = {
    message: new Set(),
    error: new Set(),
    status: new Set(),
  };
  const pending = new Map<string, OutboundMessage>();
  const inbound = new Map<string, InboundMessage>();
  const recentReceived = new Map<string, number>();
  const slotWaiters: Array<ReturnType<typeof createDeferred<void>>> = [];
  const stats: XferStats = {
    sentMessages: 0,
    receivedMessages: 0,
    resentMessages: 0,
    droppedMessages: 0,
  };
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
    const requireAck =
      sendOptions?.requireAck ?? reliability.requireAck ?? true;
    const ackTimeoutMs = clampMs(
      sendOptions?.timeoutMs ?? reliability.ackTimeoutMs ?? 2500,
      50
    );
    const message = await buildOutboundMessage(data, requireAck, ackTimeoutMs);
    await waitForSlot(requireAck);
    dispatchMessage(message);
    return message.deferred.promise;
  };

  const on = (event: XferEvent, handler: XferHandler) => {
    listeners[event].add(handler);
    return () => {
      listeners[event].delete(handler);
    };
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
    listeners.message.clear();
    listeners.error.clear();
    listeners.status.clear();
    slotWaiters.splice(0).forEach((waiter) => waiter.reject());
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

  const waitForSlot = async (requireAck: boolean) => {
    if (!requireAck) {
      return;
    }
    if (inFlight < (reliability.maxInFlight ?? 16)) {
      return;
    }
    const waiter = createDeferred<void>();
    slotWaiters.push(waiter);
    await waiter.promise;
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
    if (message.retriesLeft <= 0) {
      pending.delete(id);
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
      emit("message", data);
      return;
    }

    if (data.channel !== channelId) {
      return;
    }

    if (isAckFrame(data)) {
      handleAck(data.id);
      return;
    }

    if (isNackFrame(data)) {
      handleNack(data.id, data.reason);
      return;
    }

    if (isDataFrame(data)) {
      await handleDataFrame(data);
    }
  };

  const handleAck = (id: string) => {
    const message = pending.get(id);
    if (!message) {
      return;
    }
    pending.delete(id);
    if (message.timer) {
      clearTimeout(message.timer);
    }
    inFlight -= 1;
    emitStatus({ type: "ack", id });
    message.deferred.resolve();
    releaseSlot();
  };

  const handleNack = (id: string, reason?: string) => {
    const message = pending.get(id);
    if (!message) {
      return;
    }
    if (message.timer) {
      clearTimeout(message.timer);
    }
    if (message.retriesLeft <= 0) {
      pending.delete(id);
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

  const handleDataFrame = async (frame: DataFrame) => {
    const duplicate = isDuplicate(frame.id);
    if (duplicate) {
      if (frame.ack) {
        sendAck(frame.id);
      }
      return;
    }

    try {
      if (frame.mode === "structured") {
        stats.receivedMessages += 1;
        markReceived(frame.id);
        emit("message", frame.payload);
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
        emit("message", decoded);
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
        emit("message", decoded);
        if (frame.ack) {
          sendAck(frame.id);
        }
      }
    } catch (err) {
      stats.droppedMessages += 1;
      emit("error", err);
      if (frame.ack) {
        sendNack(frame.id, err instanceof Error ? err.message : "decode_error");
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
        updatedAt: nowMs(),
      };
      inbound.set(frame.id, entry);
    } else {
      entry.format = entry.format ?? frame.format;
      entry.binType = entry.binType ?? frame.binType;
      entry.codec = entry.codec ?? frame.codec;
      entry.iv = entry.iv ?? frame.iv;
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
    const dedupeCutoff = nowMs() - (reliability.dedupeWindowMs ?? 60_000);
    for (const [id, ts] of recentReceived.entries()) {
      if (ts < dedupeCutoff) {
        recentReceived.delete(id);
      }
    }
  };

  const sendAck = (id: string) => {
    const frame: Frame = {
      __xferkit: 1,
      v: 1,
      kind: "ack",
      channel: channelId,
      id,
    };
    postMessageTarget(target, frame, undefined, options.targetOrigin);
  };

  const sendNack = (id: string, reason?: string) => {
    const frame: Frame = {
      __xferkit: 1,
      v: 1,
      kind: "nack",
      channel: channelId,
      id,
      reason,
    };
    postMessageTarget(target, frame, undefined, options.targetOrigin);
  };

  const emitStatus = (status: XferStatus) => {
    emit("status", status);
  };

  const buildOutboundMessage = async (
    data: unknown,
    requireAck: boolean,
    ackTimeoutMs: number
  ): Promise<OutboundMessage> => {
    const hasCodec = Boolean(options.codec?.compress || options.codec?.encrypt);
    const chunkLimit = options.chunk?.maxBytes;
    const chunkEnabled = typeof chunkLimit === "number" && chunkLimit > 0;
    const forceBinary = hasCodec || chunkEnabled;
    const id = createId("msg");
    const retries = requireAck ? reliability.maxRetries ?? 0 : 0;
    const backoffMs = reliability.retryBackoffMs ?? 200;
    const allowTransfer = options.transfer?.auto !== false && supportsTransfer(target);
    const frameBase = {
      __xferkit: 1 as const,
      v: 1 as const,
      kind: "data" as const,
      channel: channelId,
      id,
      ack: requireAck ? 1 : undefined,
    };

    if (!forceBinary) {
      const transferList =
        allowTransfer && retries === 0 ? collectTransferables(data) : undefined;
      return {
        id,
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
        deferred: createDeferred<void>(),
      };
    }

    const raw = encodeBinaryPayload(data);
    const encoded = await applyCodecEncode(raw.bytes, options.codec);
    const chunks = chunkBytes(encoded.bytes, chunkEnabled ? chunkLimit : undefined);
    const ivBuffer = encoded.iv ? toArrayBuffer(encoded.iv) : undefined;
    const frames: OutboundFrameSpec[] = chunks.map((chunk, index) => ({
      base: {
        ...frameBase,
        mode: "binary",
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
    }));

    return {
      id,
      frames,
      requireAck,
      retriesLeft: retries,
      ackTimeoutMs,
      backoffMs,
      attempt: 0,
      deferred: createDeferred<void>(),
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
    if (ArrayBuffer.isView(payload)) {
      return new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
    }
    return null;
  };

  const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
    if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
      return bytes.buffer;
    }
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  };

  return { send, on, close, getStats };
}
