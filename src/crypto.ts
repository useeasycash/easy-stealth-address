/**
 * Cryptographic utilities for Solana stealth address operations
 * Uses ed25519 elliptic curve (Solana standard)
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  randomBytes,
  bytesToHex as nobleBytesToHex,
  hexToBytes as nobleHexToBytes,
} from "@noble/hashes/utils";
import bs58 from "bs58";
import type { KeyPair, Base58String } from "./types";

const PRIVATE_KEY_SIZE = 32;
const PUBLIC_KEY_SIZE = 32;

/**
 * Custom error class for cryptographic operations
 */
export class CryptoError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = "CryptoError";
  }
}

/**
 * Validate private key format and range
 */
export function isValidPrivateKey(key: Uint8Array): boolean {
  return key.length === PRIVATE_KEY_SIZE;
}

/**
 * Validate public key format
 */
export function isValidPublicKey(key: Uint8Array): boolean {
  if (key.length !== PUBLIC_KEY_SIZE) return false;
  try {
    ed25519.ExtendedPoint.fromHex(key);
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate a random private key
 */
export function generatePrivateKey(): Uint8Array {
  return randomBytes(PRIVATE_KEY_SIZE);
}

/**
 * Derive public key from private key
 */
export function getPublicKey(privateKey: Uint8Array): Uint8Array {
  if (!isValidPrivateKey(privateKey)) {
    throw new CryptoError("Invalid private key", "INVALID_PRIVATE_KEY");
  }
  try {
    return ed25519.getPublicKey(privateKey);
  } catch (err) {
    throw new CryptoError(
      `Failed to derive public key: ${err instanceof Error ? err.message : "Unknown error"}`,
      "PUBLIC_KEY_DERIVATION_FAILED",
    );
  }
}

/**
 * Generate a new key pair
 */
export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivateKey();
  const publicKey = getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Perform scalar multiplication (ECDH-like) on Ed25519
 * result = scalar * Point
 */
export function computeSharedSecret(
  scalar: Uint8Array,
  point: Uint8Array,
): Uint8Array {
  if (!isValidPrivateKey(scalar)) {
    throw new CryptoError("Invalid scalar", "INVALID_SCALAR");
  }
  if (!isValidPublicKey(point)) {
    throw new CryptoError("Invalid public key point", "INVALID_PUBLIC_KEY");
  }
  try {
    const p = ed25519.ExtendedPoint.fromHex(point);
    // multiply returns a Point, we need bytes (compressed / 32 bytes)
    return p.multiply(bytesToBigInt(scalar)).toRawBytes();
  } catch (err) {
    throw new CryptoError(
      `Shared secret computation failed: ${err instanceof Error ? err.message : "Unknown error"}`,
      "SHARED_SECRET_FAILED",
    );
  }
}

/**
 * Point addition on the curve
 * P_result = P1 + P2
 */
export function pointAdd(point1: Uint8Array, point2: Uint8Array): Uint8Array {
  if (!isValidPublicKey(point1) || !isValidPublicKey(point2)) {
    throw new CryptoError("Invalid points for addition", "INVALID_POINT");
  }
  try {
    const p1 = ed25519.ExtendedPoint.fromHex(point1);
    const p2 = ed25519.ExtendedPoint.fromHex(point2);
    return p1.add(p2).toRawBytes();
  } catch (err) {
    throw new CryptoError(
      `Point addition failed: ${err instanceof Error ? err.message : "Unknown error"}`,
      "POINT_ADDITION_FAILED",
    );
  }
}

/**
 * Add two scalars modulo curve order
 * s_result = (s1 + s2) mod L
 */
export function scalarAdd(
  scalar1: Uint8Array,
  scalar2: Uint8Array,
): Uint8Array {
  if (
    scalar1.length !== PRIVATE_KEY_SIZE ||
    scalar2.length !== PRIVATE_KEY_SIZE
  ) {
    throw new CryptoError("Scalars must be 32 bytes", "INVALID_SCALAR_LENGTH");
  }
  try {
    const l = ed25519.CURVE.n;
    const s1 = bytesToBigInt(scalar1);
    const s2 = bytesToBigInt(scalar2);
    const result = (s1 + s2) % l;
    return bigIntToBytes(result, PRIVATE_KEY_SIZE); // Little-endian usually for Ed25519
  } catch (err) {
    throw new CryptoError(
      `Scalar addition failed: ${err instanceof Error ? err.message : "Unknown error"}`,
      "SCALAR_ADDITION_FAILED",
    );
  }
}

/**
 * Hash data using sha256
 */
import { sha256 } from "@noble/hashes/sha256";

export function hashSharedSecret(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Convert bytes to Base58 string (Solana Address Format)
 */
export function bytesToBase58(bytes: Uint8Array): Base58String {
  if (!(bytes instanceof Uint8Array)) {
    throw new CryptoError("Input must be Uint8Array", "INVALID_INPUT");
  }
  return bs58.encode(bytes);
}

/**
 * Convert Base58 string to bytes
 */
export function base58ToBytes(str: string): Uint8Array {
  if (typeof str !== "string") {
    throw new CryptoError("Input must be a string", "INVALID_INPUT");
  }
  try {
    return bs58.decode(str);
  } catch (err) {
    throw new CryptoError("Invalid Base58 string", "INVALID_BASE58");
  }
}

/**
 * Extract view tag from hash (first byte)
 */
export function extractViewTag(hash: Uint8Array): number {
  if (hash.length === 0) {
    throw new CryptoError("Empty hash", "EMPTY_HASH");
  }
  return hash[0];
}

/**
 * Utilities
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  // Little endian for Ed25519
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) + BigInt(bytes[i]);
  }
  return result;
}

export function bigIntToBytes(value: bigint, length: number): Uint8Array {
  // Little endian for Ed25519
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(remaining & 0xffn);
    remaining = remaining >> 8n;
  }
  return bytes;
}

// Convert big-endian hex (for debugging)
export function bytesToHex(bytes: Uint8Array): string {
  return nobleBytesToHex(bytes);
}
export function hexToBytes(hex: string): Uint8Array {
  return nobleHexToBytes(hex);
}
