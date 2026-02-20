# Arroz Wallet

A Stellar wallet built in Python with both a command-line interface and a web UI. Supports testnet and mainnet.

## Features

- **Create a wallet** — generate a new keypair, encrypted with a password you choose
- **Check balance** — view your XLM balance via the Horizon API
- **Send XLM** — send payments to any Stellar address (password required to sign)
- **Transaction history** — view your 10 most recent transactions
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

The web UI exposes all wallet features — dashboard, create wallet, send XLM, and transaction history. Network selection (testnet/mainnet) is available in the navbar and applies immediately.

#### Testnet quickstart (web)

1. Run `python3 app.py` and open http://localhost:5001
2. Click **Create Wallet**, choose a password, and submit — the account is funded automatically via Friendbot
3. If you already have a wallet that isn't funded yet, click **Fund with Friendbot** on the dashboard

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
║  6. Exit                 ║
╚══════════════════════════╝
```

#### Testnet quickstart (CLI)

1. Run the script and select **Testnet**
2. Choose **Create new wallet** — you'll be offered free testnet XLM via Friendbot
3. Use the menu to check your balance, send payments, and view history

## Security

The secret key is encrypted at rest using a password you set when creating the wallet.

- **Encryption:** [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256)
- **Key derivation:** PBKDF2HMAC with SHA-256 and 480,000 iterations — makes brute-force attacks slow even if `wallet.json` is stolen
- **Random salt:** a unique 16-byte salt is generated per wallet and stored alongside the encrypted secret
- **Password input:** entered via `getpass` (CLI) or an HTML password field (web) — used server-side only and never stored
- **In-memory only:** the plaintext secret key is decrypted in memory only when signing a transaction, and never written to disk

`wallet.json` stores three fields: `public_key`, `encrypted_secret`, and `salt`. No plaintext secret key is ever saved.

`wallet.json` is excluded from git via `.gitignore`. Never share it or your password.

## Built with

- [stellar-sdk](https://github.com/StellarCN/py-stellar-base) — Python SDK for Stellar
- [Horizon API](https://developers.stellar.org/api/horizon) — Stellar's REST API
- [cryptography](https://cryptography.io) — Fernet encryption + PBKDF2HMAC key derivation
- [Flask](https://flask.palletsprojects.com) — web framework for the browser UI
- [Bootstrap 5](https://getbootstrap.com) — styling for the web UI
