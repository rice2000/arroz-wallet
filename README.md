# Arroz Wallet

A simple command-line Stellar wallet built in Python. Supports both testnet and mainnet.

## Features

- **Create a wallet** — generate a new keypair, encrypted with a password you choose
- **Check balance** — view your XLM balance via the Horizon API
- **Send XLM** — send payments to any Stellar address (password required to sign)
- **Transaction history** — view your 10 most recent transactions
- **Testnet + Mainnet** — choose your network at startup
- **Encrypted secret key** — your secret key is never stored in plaintext

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

### Testnet quickstart

1. Run the script and select **Testnet**
2. Choose **Create new wallet** — you'll be offered free testnet XLM via Friendbot
3. Use the menu to check your balance, send payments, and view history

## Security

The secret key is encrypted at rest using a password you set when creating the wallet.

- **Encryption:** [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256)
- **Key derivation:** PBKDF2HMAC with SHA-256 and 480,000 iterations — makes brute-force attacks slow even if `wallet.json` is stolen
- **Random salt:** a unique 16-byte salt is generated per wallet and stored alongside the encrypted secret
- **Password input:** entered via `getpass` — never displayed on screen
- **In-memory only:** the plaintext secret key is decrypted in memory only when signing a transaction, and never written to disk

`wallet.json` stores three fields: `public_key`, `encrypted_secret`, and `salt`. No plaintext secret key is ever saved.

`wallet.json` is excluded from git via `.gitignore`. Never share it or your password.

## Built with

- [stellar-sdk](https://github.com/StellarCN/py-stellar-base) — Python SDK for Stellar
- [Horizon API](https://developers.stellar.org/api/horizon) — Stellar's REST API
- [cryptography](https://cryptography.io) — Fernet encryption + PBKDF2HMAC key derivation
