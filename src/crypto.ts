/**
 * Cryptographic utilities for stealth address operations
 * Uses secp256k1 elliptic curve (same as Ethereum)
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { randomBytes } from '@noble/hashes/utils';
import type { KeyPair, HexString } from './types';

const PRIVATE_KEY_SIZE = 32;
const COMPRESSED_PUBLIC_KEY_SIZE = 33;
const UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;

/**
 * Custom error class for cryptographic operations
 */
export class CryptoError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

/**
 * Validate private key format and range
 */
export function isValidPrivateKey(key: Uint8Array): boolean {
  if (key.length !== PRIVATE_KEY_SIZE) return false;
  try {
    const scalar = bytesToBigInt(key);
    return scalar > 0n && scalar < secp256k1.CURVE.n;
  } catch {
    return false;
  }
}

/**
 * Validate public key format
 */
export function isValidPublicKey(key: Uint8Array): boolean {
  if (
    key.length !== COMPRESSED_PUBLIC_KEY_SIZE &&
    key.length !== UNCOMPRESSED_PUBLIC_KEY_SIZE
  ) {
    return false;
  }
  try {
    secp256k1.ProjectivePoint.fromHex(key);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate hex string format
 */
export function isValidHex(hex: string): boolean {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  return cleanHex.length > 0 && cleanHex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleanHex);
}

/**
 * Generate a random private key
 */
export function generatePrivateKey(): Uint8Array {
  let key: Uint8Array;
  let attempts = 0;
  const maxAttempts = 100;

  do {
    key = randomBytes(PRIVATE_KEY_SIZE);
    attempts++;
    if (attempts >= maxAttempts) {
      throw new CryptoError('Failed to generate valid private key', 'KEY_GENERATION_FAILED');
    }
  } while (!isValidPrivateKey(key));

  return key;
}

/**
 * Derive public key from private key
 */
export function getPublicKey(privateKey: Uint8Array): Uint8Array {
  if (!isValidPrivateKey(privateKey)) {
    throw new CryptoError('Invalid private key', 'INVALID_PRIVATE_KEY');
  }
  try {
    return secp256k1.getPublicKey(privateKey, true);
  } catch (err) {
    throw new CryptoError(
      `Failed to derive public key: ${err instanceof Error ? err.message : 'Unknown error'}`,
      'PUBLIC_KEY_DERIVATION_FAILED'
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
 * Perform ECDH to get shared secret
 */
export function computeSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  if (!isValidPrivateKey(privateKey)) {
    throw new CryptoError('Invalid private key for ECDH', 'INVALID_PRIVATE_KEY');
  }
  if (!isValidPublicKey(publicKey)) {
    throw new CryptoError('Invalid public key for ECDH', 'INVALID_PUBLIC_KEY');
  }
  try {
    const sharedPoint = secp256k1.getSharedSecret(privateKey, publicKey);
    return sharedPoint.slice(1);
  } catch (err) {
    throw new CryptoError(
      `ECDH computation failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
      'ECDH_FAILED'
    );
  }
}

/**
 * Hash data using keccak256
 */
export function keccak256(data: Uint8Array): Uint8Array {
  if (!(data instanceof Uint8Array)) {
    throw new CryptoError('Input must be Uint8Array', 'INVALID_INPUT');
  }
  return keccak_256(data);
}

/**
 * Derive Ethereum address from public key
 */
export function publicKeyToAddress(publicKey: Uint8Array): string {
  if (!isValidPublicKey(publicKey)) {
    throw new CryptoError('Invalid public key for address derivation', 'INVALID_PUBLIC_KEY');
  }
  try {
    const uncompressed = secp256k1.ProjectivePoint.fromHex(publicKey)
      .toRawBytes(false)
      .slice(1);
    const hash = keccak256(uncompressed);
    const addressBytes = hash.slice(-20);
    return bytesToHex(addressBytes);
  } catch (err) {
    throw new CryptoError(
      `Address derivation failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
      'ADDRESS_DERIVATION_FAILED'
    );
  }
}

/**
 * Point addition on the curve
 */
export function pointAdd(point1: Uint8Array, point2: Uint8Array): Uint8Array {
  if (!isValidPublicKey(point1)) {
    throw new CryptoError('Invalid first point for addition', 'INVALID_POINT');
  }
  if (!isValidPublicKey(point2)) {
    throw new CryptoError('Invalid second point for addition', 'INVALID_POINT');
  }
  try {
    const p1 = secp256k1.ProjectivePoint.fromHex(point1);
    const p2 = secp256k1.ProjectivePoint.fromHex(point2);
    return p1.add(p2).toRawBytes(true);
  } catch (err) {
    throw new CryptoError(
      `Point addition failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
      'POINT_ADDITION_FAILED'
    );
  }
}

/**
 * Add two scalars modulo curve order
 */
export function scalarAdd(scalar1: Uint8Array, scalar2: Uint8Array): Uint8Array {
  if (scalar1.length !== PRIVATE_KEY_SIZE || scalar2.length !== PRIVATE_KEY_SIZE) {
    throw new CryptoError('Scalars must be 32 bytes', 'INVALID_SCALAR_LENGTH');
  }
  try {
    const n = secp256k1.CURVE.n;
    const s1 = bytesToBigInt(scalar1);
    const s2 = bytesToBigInt(scalar2);
    const result = (s1 + s2) % n;
    return bigIntToBytes(result, PRIVATE_KEY_SIZE);
  } catch (err) {
    throw new CryptoError(
      `Scalar addition failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
      'SCALAR_ADDITION_FAILED'
    );
  }
}

/**
 * Extract view tag from shared secret (first byte)
 */
export function extractViewTag(sharedSecretHash: Uint8Array): number {
  if (sharedSecretHash.length === 0) {
    throw new CryptoError('Empty hash for view tag extraction', 'EMPTY_HASH');
  }
  return sharedSecretHash[0];
}

/**
 * Convert bytes to hex string with 0x prefix
 */
export function bytesToHex(bytes: Uint8Array): HexString {
  if (!(bytes instanceof Uint8Array)) {
    throw new CryptoError('Input must be Uint8Array', 'INVALID_INPUT');
  }
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `0x${hex}`;
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new CryptoError('Input must be a string', 'INVALID_INPUT');
  }
  if (!isValidHex(hex)) {
    throw new CryptoError('Invalid hex string format', 'INVALID_HEX');
  }
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to BigInt
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  if (!(bytes instanceof Uint8Array)) {
    throw new CryptoError('Input must be Uint8Array', 'INVALID_INPUT');
  }
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

/**
 * Convert BigInt to bytes with specified length
 */
export function bigIntToBytes(value: bigint, length: number): Uint8Array {
  if (typeof value !== 'bigint' || value < 0n) {
    throw new CryptoError('Value must be a non-negative BigInt', 'INVALID_VALUE');
  }
  if (length <= 0) {
    throw new CryptoError('Length must be positive', 'INVALID_LENGTH');
  }
  const bytes = new Uint8Array(length);
  let remaining = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn);
    remaining = remaining >> 8n;
  }
  return bytes;
}
