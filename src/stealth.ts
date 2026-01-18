/**
 * Stealth Address Implementation
 * Based on EIP-5564 standard for stealth addresses
 *
 * Flow:
 * 1. Receiver generates stealth meta-address (spending + viewing keys)
 * 2. Sender generates ephemeral key and computes stealth address
 * 3. Sender publishes ephemeral public key
 * 4. Receiver scans announcements and recovers stealth private key
 */

import {
  generateKeyPair,
  getPublicKey,
  computeSharedSecret,
  keccak256,
  publicKeyToAddress,
  pointAdd,
  scalarAdd,
  extractViewTag,
  bytesToHex,
  hexToBytes,
  isValidPublicKey,
  isValidHex,
  CryptoError,
} from './crypto';

import type {
  StealthKeys,
  StealthMetaAddress,
  StealthAddressResult,
  RecoveredAddress,
  StealthAnnouncement,
  HexString,
  ScanOptions,
  ScanProgress,
} from './types';

const DEFAULT_BATCH_SIZE = 100;

/**
 * Generate new stealth keys for a receiver
 * Creates both spending and viewing key pairs
 */
export function generateStealthKeys(): StealthKeys {
  return {
    spendingKey: generateKeyPair(),
    viewingKey: generateKeyPair(),
  };
}

/**
 * Get the stealth meta-address from stealth keys
 * This is what receivers share publicly
 */
export function getStealthMetaAddress(keys: StealthKeys): StealthMetaAddress {
  return {
    spendingPublicKey: keys.spendingKey.publicKey,
    viewingPublicKey: keys.viewingKey.publicKey,
  };
}

/**
 * Encode stealth meta-address to string format
 * Format: st:eth:0x<spendingPubKey><viewingPubKey>
 */
export function encodeStealthMetaAddress(meta: StealthMetaAddress): string {
  if (!isValidPublicKey(meta.spendingPublicKey)) {
    throw new CryptoError('Invalid spending public key', 'INVALID_PUBLIC_KEY');
  }
  if (!isValidPublicKey(meta.viewingPublicKey)) {
    throw new CryptoError('Invalid viewing public key', 'INVALID_PUBLIC_KEY');
  }
  const spending = bytesToHex(meta.spendingPublicKey).slice(2);
  const viewing = bytesToHex(meta.viewingPublicKey).slice(2);
  return `st:eth:0x${spending}${viewing}`;
}

/**
 * Decode stealth meta-address from string format
 */
export function decodeStealthMetaAddress(encoded: string): StealthMetaAddress {
  const prefix = 'st:eth:0x';
  if (!encoded.startsWith(prefix)) {
    throw new CryptoError('Invalid stealth meta-address format: missing prefix', 'INVALID_FORMAT');
  }

  const data = encoded.slice(prefix.length);
  const keyLength = 66; // 33 bytes compressed public key = 66 hex chars

  if (data.length !== keyLength * 2) {
    throw new CryptoError(
      `Invalid stealth meta-address length: expected ${keyLength * 2}, got ${data.length}`,
      'INVALID_LENGTH'
    );
  }

  if (!isValidHex(data)) {
    throw new CryptoError('Invalid hex in stealth meta-address', 'INVALID_HEX');
  }

  const spendingPublicKey = hexToBytes(data.slice(0, keyLength));
  const viewingPublicKey = hexToBytes(data.slice(keyLength));

  if (!isValidPublicKey(spendingPublicKey)) {
    throw new CryptoError('Invalid spending public key in meta-address', 'INVALID_PUBLIC_KEY');
  }
  if (!isValidPublicKey(viewingPublicKey)) {
    throw new CryptoError('Invalid viewing public key in meta-address', 'INVALID_PUBLIC_KEY');
  }

  return { spendingPublicKey, viewingPublicKey };
}

/**
 * Generate a stealth address for sending funds
 * Called by the sender with receiver's meta-address
 *
 * @param metaAddress - Receiver's stealth meta-address
 * @returns Stealth address, ephemeral public key, and view tag
 */
export function generateStealthAddress(
  metaAddress: StealthMetaAddress
): StealthAddressResult {
  if (!isValidPublicKey(metaAddress.spendingPublicKey)) {
    throw new CryptoError('Invalid spending public key in meta-address', 'INVALID_PUBLIC_KEY');
  }
  if (!isValidPublicKey(metaAddress.viewingPublicKey)) {
    throw new CryptoError('Invalid viewing public key in meta-address', 'INVALID_PUBLIC_KEY');
  }

  const ephemeral = generateKeyPair();

  const sharedSecret = computeSharedSecret(
    ephemeral.privateKey,
    metaAddress.viewingPublicKey
  );

  const sharedSecretHash = keccak256(sharedSecret);
  const viewTag = extractViewTag(sharedSecretHash);

  const stealthPublicKey = pointAdd(
    metaAddress.spendingPublicKey,
    getPublicKey(sharedSecretHash)
  );

  const stealthAddress = publicKeyToAddress(stealthPublicKey);

  return {
    stealthAddress,
    ephemeralPublicKey: ephemeral.publicKey,
    viewTag,
  };
}

/**
 * Check if a stealth address belongs to the receiver using view tag
 * Fast check before doing full computation
 *
 * @param viewingPrivateKey - Receiver's viewing private key
 * @param ephemeralPublicKey - From announcement
 * @param expectedViewTag - From announcement
 * @returns true if view tag matches (likely belongs to receiver)
 */
export function checkStealthAddress(
  viewingPrivateKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  expectedViewTag: number
): boolean {
  try {
    const sharedSecret = computeSharedSecret(viewingPrivateKey, ephemeralPublicKey);
    const sharedSecretHash = keccak256(sharedSecret);
    const computedViewTag = extractViewTag(sharedSecretHash);
    return computedViewTag === expectedViewTag;
  } catch {
    return false;
  }
}

/**
 * Recover the stealth address private key
 * Called by receiver after confirming ownership
 *
 * @param spendingPrivateKey - Receiver's spending private key
 * @param viewingPrivateKey - Receiver's viewing private key
 * @param ephemeralPublicKey - From announcement
 * @returns The stealth address and its private key
 */
export function recoverStealthPrivateKey(
  spendingPrivateKey: Uint8Array,
  viewingPrivateKey: Uint8Array,
  ephemeralPublicKey: Uint8Array
): RecoveredAddress {
  const sharedSecret = computeSharedSecret(viewingPrivateKey, ephemeralPublicKey);
  const sharedSecretHash = keccak256(sharedSecret);

  const stealthPrivateKey = scalarAdd(spendingPrivateKey, sharedSecretHash);

  const stealthPublicKey = getPublicKey(stealthPrivateKey);
  const address = publicKeyToAddress(stealthPublicKey);

  return {
    address,
    privateKey: stealthPrivateKey,
  };
}

/**
 * Validate an announcement object
 */
function isValidAnnouncement(announcement: StealthAnnouncement): boolean {
  return (
    typeof announcement.stealthAddress === 'string' &&
    announcement.stealthAddress.startsWith('0x') &&
    typeof announcement.ephemeralPublicKey === 'string' &&
    isValidHex(announcement.ephemeralPublicKey) &&
    typeof announcement.viewTag === 'number' &&
    announcement.viewTag >= 0 &&
    announcement.viewTag <= 255
  );
}

/**
 * Scan announcements to find stealth addresses belonging to receiver
 *
 * @param keys - Receiver's stealth keys
 * @param announcements - List of stealth announcements to scan
 * @returns Recovered addresses with private keys
 */
export function scanAnnouncements(
  keys: StealthKeys,
  announcements: StealthAnnouncement[]
): RecoveredAddress[] {
  const recovered: RecoveredAddress[] = [];

  for (const announcement of announcements) {
    if (!isValidAnnouncement(announcement)) {
      continue;
    }

    try {
      const ephemeralPublicKey = hexToBytes(announcement.ephemeralPublicKey);

      const isMatch = checkStealthAddress(
        keys.viewingKey.privateKey,
        ephemeralPublicKey,
        announcement.viewTag
      );

      if (isMatch) {
        const result = recoverStealthPrivateKey(
          keys.spendingKey.privateKey,
          keys.viewingKey.privateKey,
          ephemeralPublicKey
        );

        if (result.address.toLowerCase() === announcement.stealthAddress.toLowerCase()) {
          recovered.push(result);
        }
      }
    } catch {
      // Skip invalid announcements
      continue;
    }
  }

  return recovered;
}

/**
 * Scan announcements in batches with progress tracking
 * Better for large announcement sets - allows cancellation and progress updates
 *
 * @param keys - Receiver's stealth keys
 * @param announcements - List of stealth announcements to scan
 * @param options - Scan options including batch size and progress callback
 * @returns Recovered addresses with private keys
 */
export async function scanAnnouncementsBatch(
  keys: StealthKeys,
  announcements: StealthAnnouncement[],
  options: ScanOptions = {}
): Promise<RecoveredAddress[]> {
  const { batchSize = DEFAULT_BATCH_SIZE, onProgress, signal } = options;
  const recovered: RecoveredAddress[] = [];
  const total = announcements.length;

  for (let i = 0; i < total; i += batchSize) {
    // Check for cancellation
    if (signal?.aborted) {
      break;
    }

    const batch = announcements.slice(i, i + batchSize);
    const batchResults = scanAnnouncements(keys, batch);
    recovered.push(...batchResults);

    // Report progress
    if (onProgress) {
      const processed = Math.min(i + batchSize, total);
      onProgress({
        total,
        processed,
        found: recovered.length,
        percentage: Math.round((processed / total) * 100),
      });
    }

    // Yield to event loop for responsiveness
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  return recovered;
}

/**
 * Create an announcement object for publishing
 */
export function createAnnouncement(
  result: StealthAddressResult
): StealthAnnouncement {
  return {
    stealthAddress: result.stealthAddress,
    ephemeralPublicKey: bytesToHex(result.ephemeralPublicKey),
    viewTag: result.viewTag,
    timestamp: Date.now(),
  };
}

/**
 * Utility: Get stealth meta-address as checksummed string
 */
export function formatMetaAddress(meta: StealthMetaAddress): {
  spending: HexString;
  viewing: HexString;
  encoded: string;
} {
  return {
    spending: bytesToHex(meta.spendingPublicKey),
    viewing: bytesToHex(meta.viewingPublicKey),
    encoded: encodeStealthMetaAddress(meta),
  };
}
