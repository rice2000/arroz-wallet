#!/usr/bin/env python3
"""
Arroz Wallet — A command-line Stellar wallet supporting testnet and mainnet.
Uses the stellar-sdk library to interact with Stellar via the Horizon API.
The secret key is encrypted with a user-chosen password and never stored in plaintext.
"""

import base64
import getpass
import json
import os
import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from stellar_sdk import Keypair, Server, Network, TransactionBuilder, Asset

# ─── Configuration ────────────────────────────────────────────────────────────

WALLET_FILE = "wallet.json"  # Local file to store the keypair

# Number of PBKDF2 iterations — higher = slower to brute-force
PBKDF2_ITERATIONS = 480_000

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


# ─── Encryption Helpers ────────────────────────────────────────────────────────

def _derive_fernet_key(password: str, salt: bytes) -> Fernet:
    """
    Derive a Fernet symmetric encryption key from a password and salt.

    PBKDF2HMAC stretches the password through many iterations of SHA-256,
    making brute-force attacks slow even if wallet.json is stolen.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,               # Fernet requires a 32-byte key
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    # Fernet expects the key as URL-safe base64
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)


def _encrypt_secret(secret_key: str, password: str) -> tuple[str, str]:
    """
    Encrypt a Stellar secret key with a password.
    Returns (encrypted_secret_hex, salt_hex) to store in wallet.json.
    """
    salt = os.urandom(16)  # Random 16-byte salt — unique per wallet
    fernet = _derive_fernet_key(password, salt)
    encrypted = fernet.encrypt(secret_key.encode())
    return encrypted.hex(), salt.hex()


def _decrypt_secret(encrypted_hex: str, salt_hex: str, password: str) -> str:
    """
    Decrypt the secret key from wallet.json using the user's password.
    Raises InvalidToken if the password is wrong.
    """
    salt = bytes.fromhex(salt_hex)
    fernet = _derive_fernet_key(password, salt)
    decrypted = fernet.decrypt(bytes.fromhex(encrypted_hex))
    return decrypted.decode()


# ─── Wallet File Helpers ───────────────────────────────────────────────────────

def load_wallet():
    """
    Read the public key from wallet.json.
    The secret key is encrypted and is NOT loaded here — use load_secret() for that.
    Returns the public key string, or None if no wallet exists.
    """
    if not os.path.exists(WALLET_FILE):
        print("No wallet found. Please create one first (option 1).")
        return None

    with open(WALLET_FILE, "r") as f:
        data = json.load(f)

    return data["public_key"]


def load_secret():
    """
    Prompt for the wallet password and decrypt the secret key.
    Returns the secret key string, or None if decryption fails.
    Called only when signing a transaction (send payment).
    """
    if not os.path.exists(WALLET_FILE):
        print("No wallet found. Please create one first (option 1).")
        return None

    with open(WALLET_FILE, "r") as f:
        data = json.load(f)

    # getpass hides the password input — it won't appear on screen
    password = getpass.getpass("Wallet password: ")

    try:
        return _decrypt_secret(data["encrypted_secret"], data["salt"], password)
    except InvalidToken:
        print("Incorrect password.")
        return None


def save_wallet(public_key: str, secret_key: str, password: str):
    """
    Encrypt the secret key and write the wallet to wallet.json.
    Only the public key, the encrypted secret, and the salt are stored —
    the plaintext secret key never touches disk.
    """
    encrypted_secret, salt = _encrypt_secret(secret_key, password)
    with open(WALLET_FILE, "w") as f:
        json.dump({
            "public_key": public_key,
            "encrypted_secret": encrypted_secret,
            "salt": salt,
        }, f, indent=2)


# ─── Feature: Create Wallet ────────────────────────────────────────────────────

def create_wallet():
    """
    Generate a new random Stellar keypair, encrypt the secret key with a
    user-chosen password, and save it to wallet.json.
    """
    # Warn the user if a wallet already exists
    if os.path.exists(WALLET_FILE):
        confirm = input("A wallet already exists. Overwrite it? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            return

    # Prompt for a password — getpass hides input so it won't appear on screen
    print("\nChoose a password to encrypt your secret key.")
    print("You'll need this password every time you send a payment.")
    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password == confirm:
            break
        print("Passwords don't match. Try again.")

    # Generate a random keypair and save it encrypted
    keypair = Keypair.random()
    save_wallet(keypair.public_key, keypair.secret, password)

    print("\nWallet created!")
    print(f"  Public Key : {keypair.public_key}")
    print(f"  Secret Key : {'*' * len(keypair.secret)}  (encrypted in {WALLET_FILE})")
    print(f"\nYour secret key is encrypted. Don't forget your password!")

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
    public_key = load_wallet()
    if public_key:
        print(f"\nYour public key (address):\n  {public_key}")


# ─── Feature: Check Balance ────────────────────────────────────────────────────

def check_balance():
    """
    Query the Horizon API for the account's balances.
    A Stellar account can hold XLM (native) plus any number of other assets.
    No password needed — the public key is enough to query balances.
    """
    public_key = load_wallet()
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
    Prompts for the wallet password to decrypt the secret key for signing.
    """
    public_key = load_wallet()
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

    # Decrypt the secret key — this is the only place it ever exists in memory
    secret_key = load_secret()
    if not secret_key:
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

        # Sign the transaction envelope with the decrypted secret key
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
    Fetch and display the 10 most recent transactions for the loaded wallet.
    No password needed — the public key is enough to query history.
    """
    public_key = load_wallet()
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
