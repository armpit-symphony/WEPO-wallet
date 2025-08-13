# WEPO Mobile Integration Guide (Self-Custodial BTC + Masternode Relay)

Audience: Mobile engineers (React Native, iOS/Swift, Android/Kotlin) integrating BTC inside the WEPO wallet with self-custody and privacy-by-default relays via masternodes.

Goal: Deliver a zero-friction, self-custodial Bitcoin wallet experience on mobile that:
- Derives keys and signs PSBTs on-device (keys never leave the device)
- Reads balances/UTXOs/history via the backend Esplora proxy endpoints
- Broadcasts via WEPO masternode relay (privacy by default), with optional fallback
- Uses the same endpoints and behavior as web, ensuring consistency

IMPORTANT backend rules
- All backend routes are prefixed with /api (Kubernetes ingress)
- Use your production base URL; do not hardcode ports
- Backends already return the required HTTP security headers

Key BTC endpoints (mobile should call these)
- GET /api/bitcoin/address/:addr
- GET /api/bitcoin/address/:addr/utxo
- GET /api/bitcoin/tx/:txid
- GET /api/bitcoin/fee-estimates
- POST /api/bitcoin/relay/broadcast { rawtx, relay_only }

Privacy model (unchanged)
- Self-custody: BIP39 → BIP84 (m/84'/0'/0') P2WPKH (bc1…); keys never leave the device
- Broadcast privacy: rawtx relayed via masternodes by default (relay_only=true). Fallback is optional if peers are not available


1) React Native reference (TypeScript)

Recommended libraries
- @scure/bip39, @scure/bip32 (no Node polyfills)
- noble-secp256k1 (ECDSA)
- bitcoinjs-lib (for PSBT) + tiny-secp256k1 (ecc binding). If you prefer, you can use a pure-TS PSBT builder instead of bitcoinjs-lib
- react-native-quick-crypto/polyfills (only if you rely on Node globals)

Derive BIP84 account + first receive address
```ts
import * as bip39 from '@scure/bip39';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';

bitcoin.initEccLib(ecc);

export function deriveBip84(mnemonic: string, passphrase = '') {
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  const root = HDKey.fromMasterSeed(seed);
  // m/84'/0'/0'
  const account = root.derive("m/84'/0'/0'");
  // receive chain m/84'/0'/0'/0/i
  const node0 = account.deriveChild(0).deriveChild(0);
  const { payments } = bitcoin;
  const p2wpkh = payments.p2wpkh({ pubkey: Buffer.from(node0.publicKey!), network: bitcoin.networks.bitcoin });
  return { account, firstReceive: p2wpkh.address! };
}
```

Read balances and UTXOs (Esplora proxy)
```ts
const API = 'https://YOUR-BACKEND-BASE-URL/api'; // DO NOT hardcode ports; keep /api prefix

export async function fetchAddressInfo(addr: string) {
  const r = await fetch(`${API}/bitcoin/address/${addr}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json(); // { success, data, txs }
}

export async function fetchUtxos(addr: string) {
  const r = await fetch(`${API}/bitcoin/address/${addr}/utxo`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).data as Array<{ txid: string; vout: number; value: number }>;
}

export async function fetchFeeEstimates() {
  const r = await fetch(`${API}/bitcoin/fee-estimates`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).data as Record<string, number>; // sats/vB
}
```

Build + sign PSBT on-device and broadcast via masternodes
```ts
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
bitcoin.initEccLib(ecc);

async function buildAndSend({
  account: HDKey,
  knownAddresses: string[],
  toAddress: string,
  amountSats: number,
  relayOnly = true,
}: {
  account: any; knownAddresses: string[]; toAddress: string; amountSats: number; relayOnly?: boolean;
}) {
  const API = 'https://YOUR-BACKEND-BASE-URL/api';

  // UTXOs across known addresses
  const utxos: Array<{ txid: string; vout: number; value: number; address: string }> = [];
  for (const addr of knownAddresses) {
    const j = await (await fetch(`${API}/bitcoin/address/${addr}/utxo`)).json();
    if (j.success && Array.isArray(j.data)) j.data.forEach((u: any) => utxos.push({ ...u, address: addr }));
  }
  if (!utxos.length) throw new Error('No UTXOs available');

  // Simple largest-first selection
  utxos.sort((a, b) => b.value - a.value);
  let selected: typeof utxos = [], total = 0;
  for (const u of utxos) { selected.push(u); total += u.value; if (total >= amountSats + 200) break; }
  if (total < amountSats) throw new Error('Insufficient funds');

  // Fee estimation (target ~2 blocks)
  const fees = await (await fetch(`${API}/bitcoin/fee-estimates`)).json();
  const feerate = (fees.data?.['2'] ?? fees.data?.['3'] ?? 15) as number; // sats/vB

  const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });
  // Inputs require nonWitnessUtxo (prev tx hex)
  for (const u of selected) {
    const tx = await (await fetch(`${API}/bitcoin/tx/${u.txid}`)).json();
    const txHex = tx.data?.hex ?? tx.data ?? tx.hex;
    psbt.addInput({ hash: u.txid, index: u.vout, nonWitnessUtxo: Buffer.from(txHex, 'hex') });
  }

  // Outputs: recipient + change (fresh change m/84'/0'/0'/1/i)
  psbt.addOutput({ address: toAddress, value: amountSats });
  const vbytes = selected.length * 150 + 2 * 34 + 10;
  const fee = Math.max(200, Math.round(feerate * vbytes));
  const change = total - amountSats - fee;
  if (change < 0) throw new Error('Insufficient funds for fee');
  if (change > 546) {
    const changeNode = account.deriveChild(1).deriveChild(0); // track index in app state
    const p2wpkhChange = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(changeNode.publicKey!), network: bitcoin.networks.bitcoin });
    psbt.addOutput({ address: p2wpkhChange.address!, value: change });
  }

  // Sign all inputs (derive by matching address index; keep an address->path map in your state)
  for (let i = 0; i < selected.length; i++) {
    const u = selected[i];
    const addrIndex = Math.max(0, knownAddresses.indexOf(u.address)); // maintain robust mapping in production
    const node = account.deriveChild(0).deriveChild(addrIndex);
    psbt.signInput(i, bitcoin.ECPair.fromPrivateKey(Buffer.from(node.privateKey!)));
  }
  psbt.finalizeAllInputs();
  const txHex = psbt.extractTransaction().toHex();

  // Broadcast via masternode relay
  const resp = await fetch(`${API}/bitcoin/relay/broadcast`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rawtx: txHex, relay_only: relayOnly })
  });
  const data = await resp.json();
  if (!resp.ok || !data.success || !data.relayed) {
    if (relayOnly && (data.path === 'relay_attempt_no_peers' || data.path === 'relay_attempt_failed')) {
      throw new Error('No masternode peers available. Tip: disable relay-only to allow fallback broadcast.');
    }
    throw new Error(data.error || `Broadcast failed (HTTP ${resp.status})`);
  }
  return { txid: data.txid, fee: fee / 1e8, path: data.path, peers: data.peers };
}
```


2) iOS (Swift) outline
- Derivation: Use CryptoKit or secp256k1 kit + BIP39/BIP32 lib (e.g., BitcoinKit.swift). Derive BIP84 account m/84'/0'/0'
- Address: Generate bech32 P2WPKH (bc1)
- Read-only: Call the same /api/bitcoin/address/:addr and /utxo endpoints; parse JSON
- PSBT: Use a Swift PSBT builder (or bridge a Rust PSBT implementation) to build, sign, and finalize
- Broadcast: POST /api/bitcoin/relay/broadcast with { rawtx, relay_only:true }
- Storage: Store mnemonic/xprv in Keychain/Secure Enclave; never send to server


3) Android (Kotlin) outline
- Derivation: Use bouncycastle or a native secp256k1 library; BIP39/BIP32 for m/84'/0'/0'
- Address: bech32 P2WPKH (bc1)
- Read-only: Same endpoints via OkHttp/Retrofit
- PSBT: Use a Kotlin PSBT library or JNI to a Rust crate
- Broadcast: POST /api/bitcoin/relay/broadcast
- Storage: Use EncryptedSharedPreferences/Keystore; never send secrets to server


4) State & UX recommendations
- Track address paths: Maintain a map address -> (change, index) to derive correct keys on signing
- New addresses: Always derive fresh receive addresses (0/i) and fresh change (1/i)
- Coin selection: Start with largest-first; later migrate to Branch-and-Bound (BnB) for better privacy/fees
- Fees: Offer Fast/Normal/Economy based on /fee-estimates
- Auto-lock: Lock sensitive actions after 15 minutes; allow biometric unlock; do not lock while miner is active
- Privacy: Default to relay_only=true; optionally expose a single fallback toggle in Settings
- Errors: If relay-only fails due to no peers, show a one-line tip to toggle fallback


5) Testing checklist (mobile)
- Derivation: Validate BIP84 addresses match reference (Electrum/Specter)
- Receive: Send small BTC to the bc1 address; verify balance/tx via /api/bitcoin/address
- Send: Build PSBT and broadcast; inspect /api/bitcoin/relay/status and relay result in UI
- No-UTXO path: Attempt send on empty wallet → user-friendly error, no crash
- Rate limiting: Keep calls paced; handle Retry-After when applicable
- Security headers: Verify HTTPS + /api prefix; no plaintext secrets in logs


6) Production notes
- Do not hardcode URLs/ports; keep /api prefix
- Keys never leave device; always sign locally
- Masternode relay preserves network privacy; fallback is optional
- Consider hiding fallback in production if you want strict privacy by default


7) Roadmap alignment (optional)
- PayJoin (BIP78) for merchant spends (2–4 weeks)
- CoinJoin via masternode coordinator (WabiSabi-like) (6–10 weeks)
- Taproot (BIP86) output support and MuSig2 later

---

Contact points
- Backend BTC endpoints live in backend/server.py
- Web wallet reference implementation in frontend/src/contexts/WalletContext.js
- Relay diagnostics endpoint: GET /api/bitcoin/relay/status

This guide keeps mobile and web aligned on derivation, privacy model, and endpoints while preserving strict self-custody for your users.