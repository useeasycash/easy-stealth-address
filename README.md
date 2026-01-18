# easy-stealth-address

> Part of the EasyCash ecosystem - Privacy-first stablecoin banking protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![$ECASH](https://img.shields.io/badge/Token-$ECASH-Live-blue)](https://easycash.finance)

## Overview

Stealth address library for private payments on Ethereum. Generate one-time addresses so senders can pay you without linking to your main wallet. Based on EIP-5564 standard.

## Features

- Generate stealth meta-addresses (share publicly)
- Create one-time stealth addresses for receiving payments
- Scan announcements to find your payments
- Recover private keys for stealth addresses
- View tag optimization for fast scanning

## Installation

```bash
npm install easy-stealth-address
```

## Quick Start

```typescript
import {
  generateStealthKeys,
  getStealthMetaAddress,
  encodeStealthMetaAddress,
  decodeStealthMetaAddress,
  generateStealthAddress,
  scanAnnouncements,
  createAnnouncement,
} from "easy-stealth-address";

// === RECEIVER: Generate and share meta-address ===
const receiverKeys = generateStealthKeys();
const metaAddress = getStealthMetaAddress(receiverKeys);
const encoded = encodeStealthMetaAddress(metaAddress);
// Share this: st:eth:0x...

// === SENDER: Generate stealth address and send payment ===
const decoded = decodeStealthMetaAddress(encoded);
const result = generateStealthAddress(decoded);
// Send funds to: result.stealthAddress
// Publish announcement with: result.ephemeralPublicKey, result.viewTag

// === RECEIVER: Scan and recover ===
const announcements = [createAnnouncement(result)];
const recovered = scanAnnouncements(receiverKeys, announcements);
// recovered[0].address - the stealth address
// recovered[0].privateKey - use this to spend funds
```

## API

### Key Management

```typescript
// Generate new stealth keys
generateStealthKeys(): StealthKeys

// Get public meta-address from keys
getStealthMetaAddress(keys: StealthKeys): StealthMetaAddress

// Encode/decode meta-address for sharing
encodeStealthMetaAddress(meta: StealthMetaAddress): string
decodeStealthMetaAddress(encoded: string): StealthMetaAddress
```

### Stealth Address Operations

```typescript
// Generate stealth address for payment
generateStealthAddress(meta: StealthMetaAddress): StealthAddressResult

// Quick check if address might be yours
checkStealthAddress(viewingKey, ephemeralPubKey, viewTag): boolean

// Recover private key for stealth address
recoverStealthPrivateKey(spendingKey, viewingKey, ephemeralPubKey): RecoveredAddress

// Scan multiple announcements
scanAnnouncements(keys: StealthKeys, announcements): RecoveredAddress[]
```

## How It Works

1. **Receiver** generates stealth keys (spending + viewing) and shares meta-address publicly
2. **Sender** generates ephemeral keypair and computes stealth address using receiver's meta-address
3. **Sender** sends funds to stealth address and publishes announcement (ephemeral pubkey + view tag)
4. **Receiver** scans announcements using viewing key to find their payments
5. **Receiver** recovers stealth private key using spending key to access funds

## $ECASH Token

**Status: LIVE**

$ECASH powers the EasyCash protocol with utilities including fee discounts, staking, governance, and yield boosting.

> **Note:** This open-source code can be used WITHOUT holding $ECASH. Value creation first, token mechanics second.

## Contributing

PRs welcome! Please follow conventional commits (`feat:`, `fix:`, `docs:`, etc).

## Links

- [Website](https://useeasy.cash)
