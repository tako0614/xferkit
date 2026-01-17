export function collectTransferables(value: unknown): Transferable[] {
  const transferables = new Set<Transferable>();
  const seen = new WeakSet<object>();

  const visit = (val: unknown) => {
    if (!val || typeof val !== "object") {
      return;
    }

    if (val instanceof ArrayBuffer) {
      transferables.add(val);
      return;
    }

    if (ArrayBuffer.isView(val)) {
      transferables.add(val.buffer);
      return;
    }

    if (typeof MessagePort !== "undefined" && val instanceof MessagePort) {
      transferables.add(val);
      return;
    }

    if (typeof ImageBitmap !== "undefined" && val instanceof ImageBitmap) {
      transferables.add(val);
      return;
    }

    if (
      typeof OffscreenCanvas !== "undefined" &&
      val instanceof OffscreenCanvas
    ) {
      transferables.add(val);
      return;
    }

    if (seen.has(val)) {
      return;
    }
    seen.add(val);

    if (Array.isArray(val)) {
      for (const item of val) {
        visit(item);
      }
      return;
    }

    if (val instanceof Map) {
      for (const [key, item] of val) {
        visit(key);
        visit(item);
      }
      return;
    }

    if (val instanceof Set) {
      for (const item of val) {
        visit(item);
      }
      return;
    }

    for (const item of Object.values(val as Record<string, unknown>)) {
      visit(item);
    }
  };

  visit(value);
  return Array.from(transferables);
}
