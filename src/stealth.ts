/**
 * Solana Stealth Address Implementation
 * Adapted from EIP-5564 logic but using Ed25519/Solana primitives.
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
  hashSharedSecret,
  pointAdd,
  scalarAdd,
  extractViewTag,
  bytesToBase58,
  base58ToBytes,
  isValidPublicKey,
  CryptoError,
} from "./crypto";

import type {
  StealthKeys,
  StealthMetaAddress,
  StealthAddressResult,
  RecoveredAddress,
  StealthAnnouncement,
  ScanOptions,
} from "./types";

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
 * Format: sol:st:<spendingBase58>:<viewingBase58>
 * (Custom format for Solana)
 */
export function encodeStealthMetaAddress(meta: StealthMetaAddress): string {
  if (!isValidPublicKey(meta.spendingPublicKey)) {
    throw new CryptoError("Invalid spending public key", "INVALID_PUBLIC_KEY");
  }
  if (!isValidPublicKey(meta.viewingPublicKey)) {
    throw new CryptoError("Invalid viewing public key", "INVALID_PUBLIC_KEY");
  }
  const spending = bytesToBase58(meta.spendingPublicKey);
  const viewing = bytesToBase58(meta.viewingPublicKey);
  return `sol:st:${spending}:${viewing}`;
}

/**
 * Decode stealth meta-address from string format
 */
export function decodeStealthMetaAddress(encoded: string): StealthMetaAddress {
  const prefix = "sol:st:";
  if (!encoded.startsWith(prefix)) {
    throw new CryptoError(
      "Invalid stealth meta-address format: missing prefix",
      "INVALID_FORMAT",
    );
  }

  const parts = encoded.slice(prefix.length).split(":");
  if (parts.length !== 2) {
    throw new CryptoError(
      "Invalid stealth meta-address format: expected 2 keys",
      "INVALID_FORMAT",
    );
  }

  const [spendingStr, viewingStr] = parts;

  try {
    const spendingPublicKey = base58ToBytes(spendingStr);
    const viewingPublicKey = base58ToBytes(viewingStr);

    if (!isValidPublicKey(spendingPublicKey)) {
      throw new CryptoError(
        "Invalid spending public key in meta-address",
        "INVALID_PUBLIC_KEY",
      );
    }
    if (!isValidPublicKey(viewingPublicKey)) {
      throw new CryptoError(
        "Invalid viewing public key in meta-address",
        "INVALID_PUBLIC_KEY",
      );
    }

    return { spendingPublicKey, viewingPublicKey };
  } catch (e) {
    if (e instanceof CryptoError) throw e;
    throw new CryptoError("Failed to decode Base58 keys", "INVALID_BASE58");
  }
}

/**
 * Generate a stealth address for sending funds on Solana
 *
 * Logic:
 * 1. Generate ephemeral key pair (r, R)
 * 2. Compute shared secret S = r * V (where V is viewing pubkey)
 * 3. Hash S to get scalar h
 * 4. Compute stealth pubkey P_stealth = P_spend + h * G
 * 5. Stealth address = Base58(P_stealth)
 *
 * @param metaAddress - Receiver's stealth meta-address
 * @returns Stealth address, ephemeral public key, and view tag
 */
export function generateStealthAddress(
  metaAddress: StealthMetaAddress,
): StealthAddressResult {
  if (!isValidPublicKey(metaAddress.spendingPublicKey)) {
    throw new CryptoError(
      "Invalid spending public key in meta-address",
      "INVALID_PUBLIC_KEY",
    );
  }
  if (!isValidPublicKey(metaAddress.viewingPublicKey)) {
    throw new CryptoError(
      "Invalid viewing public key in meta-address",
      "INVALID_PUBLIC_KEY",
    );
  }

  // 1. Ephemeral Key
  const ephemeral = generateKeyPair();

  // 2. Shared Secret (S = r * V)
  // Input: ephemeral private key (scalar), viewing public key (point)
  const sharedSecretPoint = computeSharedSecret(
    ephemeral.privateKey,
    metaAddress.viewingPublicKey,
  );

  // 3. Hash shared secret to get blinding factor/scalar
  // Use hashSharedSecret to get random bytes, then interpret as scalar
  const sharedSecretHash = hashSharedSecret(sharedSecretPoint);

  // 4. View Tag (for parsing)
  const viewTag = extractViewTag(sharedSecretHash);

  // 5. Compute Stealth Public Key
  // P_stealth = P_spend + hash(S) * G
  // We need G * hash(S). Since we don't have direct "mul base" exposed easily in our crypto utils
  // w/o circular dep or extra code, we can use getPublicKey() which does scalar * G.
  const blindingPoint = getPublicKey(sharedSecretHash); // P_blind = H(S) * G
  const stealthPublicKey = pointAdd(
    metaAddress.spendingPublicKey,
    blindingPoint,
  );

  // 6. Address
  const stealthAddress = bytesToBase58(stealthPublicKey);

  return {
    stealthAddress,
    ephemeralPublicKey: ephemeral.publicKey,
    viewTag,
  };
}

/**
 * Check if a stealth address belongs to the receiver using view tag
 *
 * @param viewingPrivateKey - Receiver's viewing private key
 * @param ephemeralPublicKey - From announcement
 * @param expectedViewTag - From announcement
 * @returns true if view tag matches
 */
export function checkStealthAddress(
  viewingPrivateKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  expectedViewTag: number,
): boolean {
  try {
    // S = v * R (where v is viewing private key, R is ephemeral pubkey)
    // Diffie-Hellman: r * V == v * R
    const sharedSecretPoint = computeSharedSecret(
      viewingPrivateKey,
      ephemeralPublicKey,
    );
    const sharedSecretHash = hashSharedSecret(sharedSecretPoint);
    const computedViewTag = extractViewTag(sharedSecretHash);
    return computedViewTag === expectedViewTag;
  } catch {
    return false;
  }
}

/**
 * Recover the stealth address private key
 *
 * Logic:
 * p_stealth = p_spend + hash(S)
 *
 * @param spendingPrivateKey - Receiver's spending private key
 * @param viewingPrivateKey - Receiver's viewing private key
 * @param ephemeralPublicKey - From announcement
 * @returns The stealth address and its private key
 */
export function recoverStealthPrivateKey(
  spendingPrivateKey: Uint8Array,
  viewingPrivateKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
): RecoveredAddress {
  // Recompute shared secret
  const sharedSecretPoint = computeSharedSecret(
    viewingPrivateKey,
    ephemeralPublicKey,
  );
  const sharedSecretHash = hashSharedSecret(sharedSecretPoint);

  // Compute stealth private key: p_stealth = p_spend + hash(S) (mod curve order)
  const stealthPrivateKey = scalarAdd(spendingPrivateKey, sharedSecretHash);

  // Verify address matches
  const stealthPublicKey = getPublicKey(stealthPrivateKey);
  const address = bytesToBase58(stealthPublicKey);

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
    typeof announcement.stealthAddress === "string" &&
    typeof announcement.ephemeralPublicKey === "string" &&
    typeof announcement.viewTag === "number" &&
    announcement.viewTag >= 0 &&
    announcement.viewTag <= 255
  );
}

/**
 * Scan announcements to find stealth addresses belonging to receiver
 */
export function scanAnnouncements(
  keys: StealthKeys,
  announcements: StealthAnnouncement[],
): RecoveredAddress[] {
  const recovered: RecoveredAddress[] = [];

  for (const announcement of announcements) {
    if (!isValidAnnouncement(announcement)) {
      continue;
    }

    try {
      const ephemeralPublicKey = base58ToBytes(announcement.ephemeralPublicKey);

      const isMatch = checkStealthAddress(
        keys.viewingKey.privateKey,
        ephemeralPublicKey,
        announcement.viewTag,
      );

      if (isMatch) {
        const result = recoverStealthPrivateKey(
          keys.spendingKey.privateKey,
          keys.viewingKey.privateKey,
          ephemeralPublicKey,
        );

        if (result.address === announcement.stealthAddress) {
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
 */
export async function scanAnnouncementsBatch(
  keys: StealthKeys,
  announcements: StealthAnnouncement[],
  options: ScanOptions = {},
): Promise<RecoveredAddress[]> {
  const { batchSize = DEFAULT_BATCH_SIZE, onProgress, signal } = options;
  const recovered: RecoveredAddress[] = [];
  const total = announcements.length;

  for (let i = 0; i < total; i += batchSize) {
    if (signal?.aborted) break;

    const batch = announcements.slice(i, i + batchSize);
    const batchResults = scanAnnouncements(keys, batch);
    recovered.push(...batchResults);

    if (onProgress) {
      const processed = Math.min(i + batchSize, total);
      onProgress({
        total,
        processed,
        found: recovered.length,
        percentage: Math.round((processed / total) * 100),
      });
    }

    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  return recovered;
}

/**
 * Create an announcement object for publishing
 */
export function createAnnouncement(
  result: StealthAddressResult,
): StealthAnnouncement {
  return {
    stealthAddress: result.stealthAddress,
    ephemeralPublicKey: bytesToBase58(result.ephemeralPublicKey),
    viewTag: result.viewTag,
    timestamp: Date.now(),
  };
}

/**
 * Utility: Get stealth meta-address details
 */
export function formatMetaAddress(meta: StealthMetaAddress): {
  spending: string;
  viewing: string;
  encoded: string;
} {
  return {
    spending: bytesToBase58(meta.spendingPublicKey),
    viewing: bytesToBase58(meta.viewingPublicKey),
    encoded: encodeStealthMetaAddress(meta),
  };
}
