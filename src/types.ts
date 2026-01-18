/**
 * Core types for stealth address operations
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
  stealthAddress: string;
  ephemeralPublicKey: Uint8Array;
  viewTag: number;
}

export interface RecoveredAddress {
  address: string;
  privateKey: Uint8Array;
}

export interface StealthAnnouncement {
  stealthAddress: string;
  ephemeralPublicKey: string;
  viewTag: number;
  timestamp: number;
}

export type HexString = `0x${string}`;

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
