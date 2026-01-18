import { describe, it, expect } from 'vitest';
import {
  generateStealthKeys,
  getStealthMetaAddress,
  encodeStealthMetaAddress,
  decodeStealthMetaAddress,
  generateStealthAddress,
  checkStealthAddress,
  recoverStealthPrivateKey,
  scanAnnouncements,
  createAnnouncement,
  bytesToHex,
} from '../src';

describe('Stealth Address', () => {
  describe('Key Generation', () => {
    it('should generate valid stealth keys', () => {
      const keys = generateStealthKeys();

      expect(keys.spendingKey.privateKey).toHaveLength(32);
      expect(keys.spendingKey.publicKey).toHaveLength(33);
      expect(keys.viewingKey.privateKey).toHaveLength(32);
      expect(keys.viewingKey.publicKey).toHaveLength(33);
    });

    it('should generate unique keys each time', () => {
      const keys1 = generateStealthKeys();
      const keys2 = generateStealthKeys();

      expect(bytesToHex(keys1.spendingKey.privateKey)).not.toBe(
        bytesToHex(keys2.spendingKey.privateKey)
      );
    });
  });

  describe('Meta Address Encoding', () => {
    it('should encode and decode stealth meta-address', () => {
      const keys = generateStealthKeys();
      const meta = getStealthMetaAddress(keys);
      const encoded = encodeStealthMetaAddress(meta);

      expect(encoded).toMatch(/^st:eth:0x[a-f0-9]+$/);

      const decoded = decodeStealthMetaAddress(encoded);
      expect(bytesToHex(decoded.spendingPublicKey)).toBe(
        bytesToHex(meta.spendingPublicKey)
      );
      expect(bytesToHex(decoded.viewingPublicKey)).toBe(
        bytesToHex(meta.viewingPublicKey)
      );
    });

    it('should throw on invalid meta-address format', () => {
      expect(() => decodeStealthMetaAddress('invalid')).toThrow();
      expect(() => decodeStealthMetaAddress('st:eth:0xshort')).toThrow();
    });
  });

  describe('Stealth Address Generation', () => {
    it('should generate valid stealth address', () => {
      const keys = generateStealthKeys();
      const meta = getStealthMetaAddress(keys);
      const result = generateStealthAddress(meta);

      expect(result.stealthAddress).toMatch(/^0x[a-f0-9]{40}$/);
      expect(result.ephemeralPublicKey).toHaveLength(33);
      expect(result.viewTag).toBeGreaterThanOrEqual(0);
      expect(result.viewTag).toBeLessThanOrEqual(255);
    });

    it('should generate different stealth address each time', () => {
      const keys = generateStealthKeys();
      const meta = getStealthMetaAddress(keys);

      const result1 = generateStealthAddress(meta);
      const result2 = generateStealthAddress(meta);

      expect(result1.stealthAddress).not.toBe(result2.stealthAddress);
    });
  });

  describe('Address Checking', () => {
    it('should correctly identify owned stealth address', () => {
      const keys = generateStealthKeys();
      const meta = getStealthMetaAddress(keys);
      const result = generateStealthAddress(meta);

      const isOwned = checkStealthAddress(
        keys.viewingKey.privateKey,
        result.ephemeralPublicKey,
        result.viewTag
      );

      expect(isOwned).toBe(true);
    });

    it('should reject unowned stealth address', () => {
      const keys1 = generateStealthKeys();
      const keys2 = generateStealthKeys();
      const meta1 = getStealthMetaAddress(keys1);
      const result = generateStealthAddress(meta1);

      const isOwned = checkStealthAddress(
        keys2.viewingKey.privateKey,
        result.ephemeralPublicKey,
        result.viewTag
      );

      expect(isOwned).toBe(false);
    });
  });

  describe('Private Key Recovery', () => {
    it('should recover correct stealth private key', () => {
      const keys = generateStealthKeys();
      const meta = getStealthMetaAddress(keys);
      const result = generateStealthAddress(meta);

      const recovered = recoverStealthPrivateKey(
        keys.spendingKey.privateKey,
        keys.viewingKey.privateKey,
        result.ephemeralPublicKey
      );

      expect(recovered.address.toLowerCase()).toBe(
        result.stealthAddress.toLowerCase()
      );
      expect(recovered.privateKey).toHaveLength(32);
    });
  });

  describe('Announcement Scanning', () => {
    it('should find owned addresses in announcements', () => {
      const keys = generateStealthKeys();
      const meta = getStealthMetaAddress(keys);

      const ownedResult = generateStealthAddress(meta);
      const ownedAnnouncement = createAnnouncement(ownedResult);

      const otherKeys = generateStealthKeys();
      const otherMeta = getStealthMetaAddress(otherKeys);
      const otherResult = generateStealthAddress(otherMeta);
      const otherAnnouncement = createAnnouncement(otherResult);

      const announcements = [ownedAnnouncement, otherAnnouncement];
      const recovered = scanAnnouncements(keys, announcements);

      expect(recovered).toHaveLength(1);
      expect(recovered[0].address.toLowerCase()).toBe(
        ownedResult.stealthAddress.toLowerCase()
      );
    });

    it('should return empty array when no owned addresses', () => {
      const keys = generateStealthKeys();
      const otherKeys = generateStealthKeys();
      const otherMeta = getStealthMetaAddress(otherKeys);
      const otherResult = generateStealthAddress(otherMeta);
      const announcements = [createAnnouncement(otherResult)];

      const recovered = scanAnnouncements(keys, announcements);

      expect(recovered).toHaveLength(0);
    });
  });

  describe('Full Flow', () => {
    it('should complete full stealth payment flow', () => {
      // 1. Receiver generates keys and shares meta-address
      const receiverKeys = generateStealthKeys();
      const metaAddress = getStealthMetaAddress(receiverKeys);
      const encodedMeta = encodeStealthMetaAddress(metaAddress);

      // 2. Sender decodes meta-address and generates stealth address
      const decodedMeta = decodeStealthMetaAddress(encodedMeta);
      const stealthResult = generateStealthAddress(decodedMeta);

      // 3. Sender publishes announcement
      const announcement = createAnnouncement(stealthResult);

      // 4. Receiver scans and recovers
      const recovered = scanAnnouncements(receiverKeys, [announcement]);

      expect(recovered).toHaveLength(1);
      expect(recovered[0].address.toLowerCase()).toBe(
        stealthResult.stealthAddress.toLowerCase()
      );

      // Receiver now has private key to spend funds
      expect(recovered[0].privateKey).toHaveLength(32);
    });
  });
});
