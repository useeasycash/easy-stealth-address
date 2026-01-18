/**
 * easy-stealth-address
 * Stealth address library for private payments
 *
 * @packageDocumentation
 */

export {
  generateStealthKeys,
  getStealthMetaAddress,
  encodeStealthMetaAddress,
  decodeStealthMetaAddress,
  generateStealthAddress,
  checkStealthAddress,
  recoverStealthPrivateKey,
  scanAnnouncements,
  scanAnnouncementsBatch,
  createAnnouncement,
  formatMetaAddress,
} from './stealth';

export {
  generateKeyPair,
  generatePrivateKey,
  getPublicKey,
  bytesToHex,
  hexToBytes,
  isValidPrivateKey,
  isValidPublicKey,
  isValidHex,
  CryptoError,
} from './crypto';

export type {
  KeyPair,
  StealthKeys,
  StealthMetaAddress,
  StealthAddressResult,
  RecoveredAddress,
  StealthAnnouncement,
  HexString,
  ScanOptions,
  ScanProgress,
} from './types';
