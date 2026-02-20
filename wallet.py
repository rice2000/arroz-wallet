#!/usr/bin/env python3
"""
Arroz Wallet — A command-line Stellar wallet supporting testnet and mainnet.
Uses the stellar-sdk library to interact with Stellar via the Horizon API.
"""

import json
import os
import requests
from stellar_sdk import Keypair, Server, Network, TransactionBuilder, Asset

# ─── Configuration ────────────────────────────────────────────────────────────

WALLET_FILE = "wallet.json"  # Local file to store the keypair

# Network configurations for testnet and mainnet
NETWORKS = {
    "testnet": {
        "name": "Testnet",
        "horizon_url": "https://horizon-testnet.stellar.org",
        "passphrase": Network.TESTNET_NETWORK_PASSPHRASE,
        "friendbot_url": "https://friendbot.stellar.org",
    },
    "mainnet": {
        "name": "Mainnet",
        "horizon_url": "https://horizon.stellar.org",
        "passphrase": Network.PUBLIC_NETWORK_PASSPHRASE,
        "friendbot_url": None,  # Friendbot does not exist on mainnet
    },
}

# These are set at startup by select_network() and used throughout
server = None
NETWORK_PASSPHRASE = None
NETWORK_NAME = None
FRIENDBOT_URL = None


# ─── Network Selection ────────────────────────────────────────────────────────

def select_network():
    """
    Ask the user to choose testnet or mainnet at startup.
    Sets the global server, passphrase, network name, and Friendbot URL.
    """
    global server, NETWORK_PASSPHRASE, NETWORK_NAME, FRIENDBOT_URL

    print("\nSelect network:")
    print("  1. Testnet  (safe for testing — no real XLM)")
    print("  2. Mainnet  (real XLM — transactions cannot be undone)")

    while True:
        choice = input("Enter 1 or 2: ").strip()
        if choice == "1":
            cfg = NETWORKS["testnet"]
            break
        elif choice == "2":
            cfg = NETWORKS["mainnet"]
            print("\n⚠  WARNING: You are connecting to MAINNET.")
            print("   All transactions use real XLM and are irreversible.")
            confirm = input("   Type 'mainnet' to confirm: ").strip().lower()
            if confirm != "mainnet":
                print("Cancelled. Defaulting to testnet.")
                cfg = NETWORKS["testnet"]
            break
        else:
            print("Please enter 1 or 2.")

    server = Server(cfg["horizon_url"])
    NETWORK_PASSPHRASE = cfg["passphrase"]
    NETWORK_NAME = cfg["name"]
    FRIENDBOT_URL = cfg["friendbot_url"]


# ─── Wallet File Helpers ───────────────────────────────────────────────────────

def load_wallet():
    """
    Read the keypair from wallet.json.
    Returns (public_key, secret_key) or (None, None) if no wallet exists.
    """
    if not os.path.exists(WALLET_FILE):
        print("No wallet found. Please create one first (option 1).")
        return None, None

    with open(WALLET_FILE, "r") as f:
        data = json.load(f)

    return data["public_key"], data["secret_key"]


def save_wallet(public_key, secret_key):
    """Write the keypair to wallet.json."""
    with open(WALLET_FILE, "w") as f:
        json.dump({"public_key": public_key, "secret_key": secret_key}, f, indent=2)


# ─── Feature: Create Wallet ────────────────────────────────────────────────────

def create_wallet():
    """
    Generate a new random Stellar keypair and save it to wallet.json.
    Optionally funds the new account via Friendbot (testnet faucet).
    """
    # Warn the user if a wallet already exists
    if os.path.exists(WALLET_FILE):
        confirm = input("A wallet already exists. Overwrite it? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            return

    # Generate a random keypair
    keypair = Keypair.random()
    save_wallet(keypair.public_key, keypair.secret)

    print("\nWallet created!")
    print(f"  Public Key : {keypair.public_key}")
    print(f"  Secret Key : {keypair.secret}")
    print(f"\nSaved to {WALLET_FILE} — keep your secret key safe!")

    # Friendbot only exists on testnet — it funds new accounts with 10,000 XLM
    if FRIENDBOT_URL:
        fund = input("\nFund this account with testnet XLM via Friendbot? (yes/no): ").strip().lower()
        if fund == "yes":
            _fund_with_friendbot(keypair.public_key)
    else:
        print("\nOn mainnet, fund this account by sending at least 1 XLM to:")
        print(f"  {keypair.public_key}")


def _fund_with_friendbot(public_key):
    """Request testnet XLM from Friendbot to activate the account on-chain."""
    print("Requesting funds from Friendbot...")
    try:
        response = requests.get(FRIENDBOT_URL, params={"addr": public_key}, timeout=15)
        if response.status_code == 200:
            print("Account funded! You now have 10,000 testnet XLM.")
        else:
            print(f"Friendbot error {response.status_code}: {response.text}")
    except requests.RequestException as e:
        print(f"Network error contacting Friendbot: {e}")


# ─── Feature: Show Address ─────────────────────────────────────────────────────

def show_address():
    """Display the public key (wallet address) from wallet.json."""
    public_key, _ = load_wallet()
    if public_key:
        print(f"\nYour public key (address):\n  {public_key}")


# ─── Feature: Check Balance ────────────────────────────────────────────────────

def check_balance():
    """
    Query the Horizon API for the account's balances.
    A Stellar account can hold XLM (native) plus any number of other assets.
    """
    public_key, _ = load_wallet()
    if not public_key:
        return

    try:
        account = server.accounts().account_id(public_key).call()
        print(f"\nBalances for {public_key}:")
        for balance in account["balances"]:
            # Native XLM has no asset_code field; everything else does
            asset_name = balance.get("asset_code", "XLM")
            print(f"  {asset_name:10s}  {balance['balance']}")
    except Exception as e:
        print(f"Error fetching balance: {e}")


# ─── Feature: Send Payment ─────────────────────────────────────────────────────

def send_payment():
    """
    Send XLM from the loaded wallet to another Stellar address.
    Builds, signs, and submits a transaction to the testnet.
    """
    public_key, secret_key = load_wallet()
    if not public_key:
        return

    destination = input("Destination public key: ").strip()
    amount = input("Amount of XLM to send: ").strip()

    # Extra confirmation on mainnet — real XLM, irreversible
    if NETWORK_NAME == "Mainnet":
        print(f"\n  Network    : {NETWORK_NAME}")
        print(f"  From       : {public_key}")
        print(f"  To         : {destination}")
        print(f"  Amount     : {amount} XLM")
        confirm = input("\n  Type 'send' to confirm this mainnet transaction: ").strip().lower()
        if confirm != "send":
            print("Cancelled.")
            return

    try:
        # Load the sender's account details (sequence number, etc.) from the network
        source_account = server.load_account(public_key)

        # Build the transaction with a single payment operation
        transaction = (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=NETWORK_PASSPHRASE,
                base_fee=100,  # fee in stroops (1 XLM = 10,000,000 stroops)
            )
            .append_payment_op(
                destination=destination,
                asset=Asset.native(),  # Asset.native() = XLM
                amount=amount,
            )
            .set_timeout(30)  # transaction expires after 30 seconds
            .build()
        )

        # Sign the transaction envelope with the sender's secret key
        keypair = Keypair.from_secret(secret_key)
        transaction.sign(keypair)

        # Submit the signed transaction to the Horizon API
        response = server.submit_transaction(transaction)
        print("\nPayment sent successfully!")
        print(f"  Transaction hash: {response['hash']}")

    except Exception as e:
        print(f"Error sending payment: {e}")


# ─── Feature: Transaction History ─────────────────────────────────────────────

def view_history():
    """
    Fetch and display the 10 most recent transactions for the loaded wallet
    using the Horizon transactions endpoint.
    """
    public_key, _ = load_wallet()
    if not public_key:
        return

    try:
        response = (
            server.transactions()
            .for_account(public_key)
            .limit(10)
            .order(desc=True)  # newest first
            .call()
        )

        records = response["_embedded"]["records"]
        if not records:
            print("No transactions found for this account.")
            return

        print(f"\nLast {len(records)} transaction(s) for {public_key}:\n")
        for i, tx in enumerate(records, 1):
            print(f"  [{i}] Hash       : {tx['hash']}")
            print(f"      Date       : {tx['created_at']}")
            print(f"      Fee paid   : {tx['fee_charged']} stroops")
            memo = tx.get("memo", "—")
            print(f"      Memo       : {memo}")
            print()

    except Exception as e:
        print(f"Error fetching transaction history: {e}")


# ─── Menu ──────────────────────────────────────────────────────────────────────

def show_menu():
    """Print the main menu and return the user's choice."""
    # Center the network name in the header (box width = 26 inner chars)
    network_line = f"Stellar {NETWORK_NAME}".center(22)
    print("\n╔══════════════════════════╗")
    print("║      Arroz  Wallet       ║")
    print(f"║  {network_line}  ║")
    print("╠══════════════════════════╣")
    print("║  1. Create new wallet    ║")
    print("║  2. Show wallet address  ║")
    print("║  3. Check balance        ║")
    print("║  4. Send payment         ║")
    print("║  5. Transaction history  ║")
    print("║  6. Exit                 ║")
    print("╚══════════════════════════╝")
    return input("Choose an option (1-6): ").strip()


# ─── Entry Point ───────────────────────────────────────────────────────────────

def main():
    """Main loop — select network, display the menu, dispatch to features."""
    print("Welcome to Arroz Wallet")
    select_network()
    print(f"\nConnected to Stellar {NETWORK_NAME}.")

    while True:
        choice = show_menu()

        if choice == "1":
            create_wallet()
        elif choice == "2":
            show_address()
        elif choice == "3":
            check_balance()
        elif choice == "4":
            send_payment()
        elif choice == "5":
            view_history()
        elif choice == "6":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 6.")


if __name__ == "__main__":
    main()
