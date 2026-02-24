# Arroz Wallet

A Stellar wallet built in Python with both a command-line interface and a web UI. Supports testnet and mainnet.

## Features

- **Create a wallet** — generate a new keypair, encrypted with a password you choose
- **Check balance** — view XLM and tracked asset balances via Stellar RPC
- **Send payments** — send XLM or any tracked asset to any Stellar address (password required to sign)
- **Transaction history** — view your 10 most recent transactions
- **Trustlines** — create on-chain trustlines directly from the wallet so your account can hold non-XLM assets
- **Manage assets** — track non-XLM assets (USDC, etc.) for balance display and sending
- **Yield vault** — deposit and withdraw USDC in a DeFindex yield vault; live APY and balance shown on the dashboard
- **Fiat on/off ramp** — convert MXN ↔ CETES via Etherfuse; on-ramp deposits CETES (tokenized Mexican treasury bills) to your wallet, off-ramp signs an outgoing Stellar tx and credits your bank account in MXN
- **Testnet + Mainnet** — switch networks at any time
- **Encrypted secret key** — your secret key is never stored in plaintext
- **Web UI** — browser-based interface via Flask (no Node.js or build step required)

## Requirements

- Python 3.8+
- pip

## Installation

```bash
git clone https://github.com/rice2000/arroz-wallet.git
cd arroz-wallet
pip install -r requirements.txt
```

## Usage

### Web UI (recommended)

```bash
python3 app.py
```

Then open **http://localhost:5001** in your browser.

> **Note:** Port 5000 is reserved by AirPlay Receiver on macOS Monterey and later, so the web UI runs on port 5001.

The web UI exposes all wallet features — dashboard, create wallet, send payments, transaction history, asset management, the yield vault, and the fiat ramp. Network selection (testnet/mainnet) is available in the navbar and applies immediately.

#### Testnet quickstart (web)

1. Run `python3 app.py` and open http://localhost:5001
2. Click **Create Wallet**, choose a password, and submit — the account is funded automatically via Friendbot
3. If you already have a wallet that isn't funded yet, click **Fund with Friendbot** on the dashboard
4. To hold USDC or another asset, go to **Assets → Create Trustline**, enter the asset code, issuer, and your password

### CLI

```bash
python3 wallet.py
```

You'll be prompted to select a network, then a menu will appear:

```
Select network:
  1. Testnet  (safe for testing — no real XLM)
  2. Mainnet  (real XLM — transactions cannot be undone)

╔══════════════════════════╗
║      Arroz  Wallet       ║
║     Stellar Testnet      ║
╠══════════════════════════╣
║  1. Create new wallet    ║
║  2. Show wallet address  ║
║  3. Check balance        ║
║  4. Send payment         ║
║  5. Transaction history  ║
║  6. Manage tracked assets║
║  7. Exit                 ║
╚══════════════════════════╝
```

#### Testnet quickstart (CLI)

1. Run the script and select **Testnet**
2. Choose **Create new wallet** — you'll be offered free testnet XLM via Friendbot
3. Use the menu to check your balance, send payments, and view history

## Trustlines

Before your account can hold any non-XLM asset, it must have an on-chain trustline for that asset. Go to **Assets** (`/assets`) and use the **Create Trustline** form:

| Field | Example (USDC on testnet) |
|-------|--------------------------|
| Asset Code | `USDC` |
| Issuer Address | `GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5` |
| Password | your wallet password |

On success the asset is added to your tracking list automatically and its balance appears on the dashboard. If you already have a trustline from another tool, use **Add to Tracking List** instead — no transaction required.

## Yield Vault (DeFindex)

The vault feature lets you earn yield on USDC by depositing into a [DeFindex](https://defindex.io) vault. To enable it, create a `defindex.json` file in the project directory:

```json
{
  "api_key": "your_defindex_api_key",
  "vaults": {
    "testnet": "TESTNET_VAULT_CONTRACT_ADDRESS",
    "mainnet": "MAINNET_VAULT_CONTRACT_ADDRESS"
  }
}
```

Once configured:

- The dashboard shows live APY, your vault balance, and TVL
- The **Vault** page (`/vault`) has deposit and withdraw forms
- Transactions are built by DeFindex, signed locally with your wallet password, and submitted via Stellar RPC — your secret key never leaves your machine

`defindex.json` is excluded from git via `.gitignore`. If the file is absent, the vault card is hidden and `/vault` redirects with a warning — no other functionality is affected.

## Fiat Ramp (Etherfuse)

The ramp feature lets you move money between MXN and CETES (Etherfuse tokenized Mexican treasury bills) via [Etherfuse](https://etherfuse.com). CETES are short-term Mexican government bonds tokenized on Stellar.

The wallet uses `api.sand.etherfuse.com` on testnet and `api.etherfuse.com` on mainnet automatically based on the selected network.

To enable the ramp, create an `etherfuse.json` file in the project directory:

```json
{
  "api_key": "your_etherfuse_api_key",
  "customer_id": "your-customer-uuid",
  "bank_account_id": "your-bank-account-uuid"
}
```

**Setup (one-time):**

1. Add your `api_key` from the Etherfuse dashboard — use the sandbox key for testnet ([devnet.etherfuse.com](https://devnet.etherfuse.com))
2. Leave `customer_id` as a placeholder — the app auto-generates one on first run and writes it back to `etherfuse.json`
3. Leave `bank_account_id` as a placeholder for now
4. Go to `/ramp` and click **Generate onboarding link** — you'll be redirected to Etherfuse's hosted UI to accept T&C, complete KYC, and add a bank account
5. After completing the onboarding flow, copy your `bank_account_id` from the Etherfuse dashboard into `etherfuse.json` and restart the app — the ramp forms will now appear
6. **Sandbox only:** contact `stablebond@etherfuse.com` with your org ID (the third segment of your `api_key`) to request proxy account provisioning before placing orders

Once configured:

- **On-ramp** — enter an MXN amount; Etherfuse handles the bank transfer and deposits CETES to your Stellar wallet. No password needed.
- **Off-ramp** — enter a CETES amount and your wallet password; the app signs and submits an outgoing Stellar transaction, and Etherfuse credits your bank account in MXN.
- **Recent orders** — the ramp page shows your last 5 orders with status. Refresh to update.

`etherfuse.json` is excluded from git via `.gitignore`. If the file is absent, `/ramp` redirects with a warning — no other functionality is affected.

## Security

The secret key is encrypted at rest using a password you set when creating the wallet.

- **Encryption:** [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256)
- **Key derivation:** PBKDF2HMAC with SHA-256 and 480,000 iterations — makes brute-force attacks slow even if `wallet.json` is stolen
- **Random salt:** a unique 16-byte salt is generated per wallet and stored alongside the encrypted secret
- **Password input:** entered via `getpass` (CLI) or an HTML password field (web) — used server-side only and never stored
- **In-memory only:** the plaintext secret key is decrypted in memory only when signing a transaction, and never written to disk

`wallet.json` stores three fields: `public_key`, `encrypted_secret`, and `salt`. No plaintext secret key is ever saved.

`wallet.json`, `defindex.json`, and `etherfuse.json` are excluded from git via `.gitignore`. Never share any of these files or your wallet password.

## Built with

- [stellar-sdk](https://github.com/StellarCN/py-stellar-base) — Python SDK for Stellar
- [Stellar RPC](https://developers.stellar.org/docs/data/rpc) — balance queries and transaction submission
- [DeFindex API](https://docs.defindex.io) — yield vault deposit/withdraw XDR generation
- [Etherfuse Ramp API](https://etherfuse.com) — fiat on/off ramp quote, order, and onboarding
- [cryptography](https://cryptography.io) — Fernet encryption + PBKDF2HMAC key derivation
- [Flask](https://flask.palletsprojects.com) — web framework for the browser UI
- [Bootstrap 5](https://getbootstrap.com) — styling for the web UI
