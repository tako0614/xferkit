import type { XferKeyring } from "./types.js";

export async function generateAesGcmKey(
  length: 128 | 192 | 256 = 256
): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return globalThis.crypto.subtle.generateKey(
    { name: "AES-GCM", length },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function generateEcdhKeyPair(
  curve: "P-256" | "P-384" | "P-521" = "P-256"
): Promise<CryptoKeyPair> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: curve },
    true,
    ["deriveKey", "deriveBits"]
  );
}

export async function exportPublicKeyRaw(
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return globalThis.crypto.subtle.exportKey("raw", publicKey);
}

export async function importPublicKeyRaw(
  raw: ArrayBuffer,
  curve: "P-256" | "P-384" | "P-521" = "P-256"
): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return globalThis.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: curve },
    true,
    []
  );
}

export async function deriveSharedAesKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  length: 128 | 192 | 256 = 256
): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return globalThis.crypto.subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    privateKey,
    { name: "AES-GCM", length },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  options?: { iterations?: number; hash?: "SHA-256" | "SHA-384" | "SHA-512" }
): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  const baseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: options?.iterations ?? 100_000,
      hash: options?.hash ?? "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportKeyRaw(key: CryptoKey): Promise<ArrayBuffer> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return globalThis.crypto.subtle.exportKey("raw", key);
}

export async function importKeyRaw(raw: ArrayBuffer): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return globalThis.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function wrapKey(
  key: CryptoKey,
  wrappingKey: CryptoKey
): Promise<{ wrapped: ArrayBuffer; iv: Uint8Array }> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  const raw = await exportKeyRaw(key);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    raw
  );
  return { wrapped, iv };
}

export async function unwrapKey(
  wrapped: ArrayBuffer,
  iv: Uint8Array,
  wrappingKey: CryptoKey
): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  const raw = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    wrapped
  );
  return importKeyRaw(raw);
}

export function createKeyring(
  current: CryptoKey,
  currentId?: string,
  keys?: Record<string, CryptoKey>
): XferKeyring {
  return { current, currentId, keys };
}

export function rotateKeyring(
  ring: XferKeyring,
  nextKey: CryptoKey,
  nextId?: string
): XferKeyring {
  const keys = { ...(ring.keys ?? {}) };
  if (ring.currentId) {
    keys[ring.currentId] = ring.current;
  }
  if (nextId) {
    keys[nextId] = nextKey;
  }
  return {
    current: nextKey,
    currentId: nextId ?? ring.currentId,
    keys,
  };
}
