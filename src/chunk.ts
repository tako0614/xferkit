export function chunkBytes(
  bytes: Uint8Array,
  maxBytes: number | undefined
): Uint8Array[] {
  if (!maxBytes || bytes.byteLength <= maxBytes) {
    return [bytes];
  }

  const chunks: Uint8Array[] = [];
  for (let offset = 0; offset < bytes.byteLength; offset += maxBytes) {
    chunks.push(bytes.subarray(offset, offset + maxBytes));
  }
  return chunks;
}

export function mergeChunks(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.byteLength;
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}
