# Arroz Wallet

A simple command-line Stellar wallet built in Python. Supports both testnet and mainnet.

## Features

- **Create a wallet** — generate a new keypair and save it locally
- **Check balance** — view your XLM balance via the Horizon API
- **Send XLM** — send payments to any Stellar address
- **Transaction history** — view your 10 most recent transactions
- **Testnet + Mainnet** — choose your network at startup

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

- Your keypair is stored in `wallet.json` in the project directory
- `wallet.json` is excluded from git via `.gitignore`
- **Never share your secret key** and never use a testnet wallet on mainnet

## Built with

- [stellar-sdk](https://github.com/StellarCN/py-stellar-base) — Python SDK for Stellar
- [Horizon API](https://developers.stellar.org/api/horizon) — Stellar's REST API
