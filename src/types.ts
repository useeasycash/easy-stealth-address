/**
 * Core types for stealth address operations (Solana Version)
 */

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface StealthKeys {
  spendingKey: KeyPair;
  viewingKey: KeyPair;
}

export interface StealthMetaAddress {
  spendingPublicKey: Uint8Array;
  viewingPublicKey: Uint8Array;
}

export interface StealthAddressResult {
  stealthAddress: Base58String;
  ephemeralPublicKey: Uint8Array;
  viewTag: number;
}

export interface RecoveredAddress {
  address: Base58String;
  privateKey: Uint8Array;
}

export interface StealthAnnouncement {
  stealthAddress: Base58String;
  ephemeralPublicKey: Base58String; // Store physically as base58 string in announcements
  viewTag: number;
  timestamp: number;
}

export type Base58String = string;

/**
 * Options for batch scanning announcements
 */
export interface ScanOptions {
  /** Number of announcements to process per batch (default: 100) */
  batchSize?: number;
  /** Callback for progress updates */
  onProgress?: (progress: ScanProgress) => void;
  /** AbortSignal for cancellation */
  signal?: AbortSignal;
}

/**
 * Progress information during scanning
 */
export interface ScanProgress {
  /** Total announcements to scan */
  total: number;
  /** Number processed so far */
  processed: number;
  /** Number of matches found so far */
  found: number;
  /** Percentage complete (0-100) */
  percentage: number;
}
