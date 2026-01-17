import type { XferTarget } from "./types.js";

export function postMessageTarget(
  target: XferTarget,
  message: unknown,
  transferList: Transferable[] | undefined,
  targetOrigin: string | undefined
) {
  if (isBroadcastChannel(target)) {
    target.postMessage(message);
    return;
  }

  if (isWindowTarget(target)) {
    const origin = targetOrigin ?? "*";
    if (transferList && transferList.length > 0) {
      (target as Window).postMessage(message, origin, transferList);
    } else {
      (target as Window).postMessage(message, origin);
    }
    return;
  }

  if (transferList && transferList.length > 0) {
    target.postMessage(message, transferList);
    return;
  }
  target.postMessage(message);
}

export function supportsTransfer(target: XferTarget): boolean {
  return !isBroadcastChannel(target);
}

function isBroadcastChannel(target: XferTarget): target is BroadcastChannel {
  return (
    typeof BroadcastChannel !== "undefined" &&
    target instanceof BroadcastChannel
  );
}

function isWindowTarget(target: XferTarget): boolean {
  return typeof Window !== "undefined" && target instanceof Window;
}
