#!/usr/bin/env python3
"""
Arroz Wallet — A command-line Stellar wallet supporting testnet and mainnet.
Uses Stellar RPC (SorobanServer) for balance queries and transaction submission.
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
from stellar_sdk import Keypair, Server, Network, TransactionBuilder, Asset, Account, SorobanServer, xdr

# ─── Configuration ────────────────────────────────────────────────────────────

WALLET_FILE = "wallet.json"  # Local file to store the keypair

# Number of PBKDF2 iterations — higher = slower to brute-force
PBKDF2_ITERATIONS = 480_000

# Network configurations for testnet and mainnet
NETWORKS = {
    "testnet": {
        "name": "Testnet",
        "horizon_url": "https://horizon-testnet.stellar.org",
        "rpc_url": "https://soroban-testnet.stellar.org",
        "passphrase": Network.TESTNET_NETWORK_PASSPHRASE,
        "friendbot_url": "https://friendbot.stellar.org",
    },
    "mainnet": {
        "name": "Mainnet",
        "horizon_url": "https://horizon.stellar.org",
        "rpc_url": "https://mainnet.sorobanrpc.com",
        "passphrase": Network.PUBLIC_NETWORK_PASSPHRASE,
        "friendbot_url": None,  # Friendbot does not exist on mainnet
    },
}

# These are set at startup by select_network() and used throughout
server = None           # Horizon — history only (TODO: migrate when Portfolio APIs are available)
soroban_server = None   # Stellar RPC — balance queries and transaction submission
NETWORK_PASSPHRASE = None
NETWORK_NAME = None
FRIENDBOT_URL = None


# ─── Network Selection ────────────────────────────────────────────────────────

def select_network():
    """
    Ask the user to choose testnet or mainnet at startup.
    Sets the global server, soroban_server, passphrase, network name, and Friendbot URL.
    """
    global server, soroban_server, NETWORK_PASSPHRASE, NETWORK_NAME, FRIENDBOT_URL

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
    soroban_server = SorobanServer(cfg["rpc_url"])
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
    Tracked assets start empty for a new wallet.
    """
    encrypted_secret, salt = _encrypt_secret(secret_key, password)
    with open(WALLET_FILE, "w") as f:
        json.dump({
            "public_key": public_key,
            "encrypted_secret": encrypted_secret,
            "salt": salt,
            "tracked_assets": [],
        }, f, indent=2)


# ─── Tracked Asset Management ─────────────────────────────────────────────────

def load_tracked_assets() -> list:
    """Return the list of tracked assets from wallet.json."""
    if not os.path.exists(WALLET_FILE):
        return []
    with open(WALLET_FILE, "r") as f:
        data = json.load(f)
    return data.get("tracked_assets", [])


def add_tracked_asset(code: str, issuer: str):
    """Add an asset to the tracked list in wallet.json (no-op if already present)."""
    if not os.path.exists(WALLET_FILE):
        return
    with open(WALLET_FILE, "r") as f:
        data = json.load(f)
    tracked = data.get("tracked_assets", [])
    for asset in tracked:
        if asset["code"] == code and asset["issuer"] == issuer:
            return  # Already tracked
    tracked.append({"code": code, "issuer": issuer})
    data["tracked_assets"] = tracked
    with open(WALLET_FILE, "w") as f:
        json.dump(data, f, indent=2)


def remove_tracked_asset(code: str, issuer: str):
    """Remove an asset from the tracked list in wallet.json."""
    if not os.path.exists(WALLET_FILE):
        return
    with open(WALLET_FILE, "r") as f:
        data = json.load(f)
    tracked = data.get("tracked_assets", [])
    data["tracked_assets"] = [
        a for a in tracked if not (a["code"] == code and a["issuer"] == issuer)
    ]
    with open(WALLET_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ─── RPC Balance Queries ───────────────────────────────────────────────────────

def get_xlm_balance(public_key: str):
    """
    Fetch native XLM balance via Stellar RPC (getLedgerEntries).
    Returns balance as a string (e.g. "9999.9999900") or None if account not found.
    """
    key = xdr.LedgerKey(
        type=xdr.LedgerEntryType.ACCOUNT,
        account=xdr.LedgerKeyAccount(
            account_id=Keypair.from_public_key(public_key).xdr_account_id()
        ),
    )
    resp = soroban_server.get_ledger_entries([key])
    if not resp.entries:
        return None  # Account not funded / doesn't exist
    account_data = xdr.LedgerEntryData.from_xdr(resp.entries[0].xdr).account
    return str(account_data.balance.int64 / 10_000_000)


def get_trustline_balance(public_key: str, asset_code: str, asset_issuer: str):
    """
    Fetch a specific trustline balance via Stellar RPC (getLedgerEntries).
    Returns balance as a string or None if trustline not found.

    Note: Stellar RPC requires knowing the asset upfront — it cannot enumerate
    all trustlines for an account. This is why we use tracked_assets in wallet.json.
    """
    asset = Asset(asset_code, asset_issuer)
    # TrustLineAsset has the same XDR encoding as Asset for alphanum4/alphanum12
    trust_line_asset = xdr.TrustLineAsset.from_xdr(asset.to_xdr_object().to_xdr())
    key = xdr.LedgerKey(
        type=xdr.LedgerEntryType.TRUSTLINE,
        trust_line=xdr.LedgerKeyTrustLine(
            account_id=Keypair.from_public_key(public_key).xdr_account_id(),
            asset=trust_line_asset,
        ),
    )
    resp = soroban_server.get_ledger_entries([key])
    if not resp.entries:
        return None
    trustline_data = xdr.LedgerEntryData.from_xdr(resp.entries[0].xdr).trust_line
    return str(trustline_data.balance.int64 / 10_000_000)


def get_all_balances(public_key: str) -> list:
    """
    Fetch XLM plus all tracked asset balances via Stellar RPC.
    Returns a list of dicts: [{"asset": "XLM", "balance": "..."}, ...]
    Returns an empty list if the account is not funded.
    """
    xlm = get_xlm_balance(public_key)
    if xlm is None:
        return []  # Account not funded

    balances = [{"asset": "XLM", "balance": xlm}]

    for tracked in load_tracked_assets():
        code = tracked["code"]
        issuer = tracked["issuer"]
        bal = get_trustline_balance(public_key, code, issuer)
        balances.append({
            "asset": code,
            "balance": bal if bal is not None else "0.0000000",
            "issuer": issuer,
        })

    return balances


def load_account_rpc(public_key: str) -> Account:
    """
    Load the account's current sequence number via Stellar RPC.
    Returns a stellar_sdk.Account object suitable for TransactionBuilder.
    Raises ValueError if the account is not funded.
    """
    key = xdr.LedgerKey(
        type=xdr.LedgerEntryType.ACCOUNT,
        account=xdr.LedgerKeyAccount(
            account_id=Keypair.from_public_key(public_key).xdr_account_id()
        ),
    )
    resp = soroban_server.get_ledger_entries([key])
    if not resp.entries:
        raise ValueError(f"Account {public_key} not found on the network — is it funded?")
    account_data = xdr.LedgerEntryData.from_xdr(resp.entries[0].xdr).account
    seq_num = account_data.seq_num.sequence_number.int64
    return Account(public_key, seq_num)


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
    Query balances via Stellar RPC — XLM plus any tracked assets.
    No password needed — the public key is enough to query balances.
    """
    public_key = load_wallet()
    if not public_key:
        return

    try:
        balances = get_all_balances(public_key)
        if not balances:
            print(f"\nAccount {public_key} has not been funded yet.")
            return
        print(f"\nBalances for {public_key}:")
        for b in balances:
            print(f"  {b['asset']:10s}  {b['balance']}")
        tracked = load_tracked_assets()
        if not tracked:
            print("\n  (Add tracked assets with 'Manage Assets' to see non-XLM balances.)")
    except Exception as e:
        print(f"Error fetching balance: {e}")


# ─── Feature: Send Payment ─────────────────────────────────────────────────────

def send_payment(asset_code=None, asset_issuer=None):
    """
    Send a payment from the loaded wallet to another Stellar address.
    Submits via Stellar RPC (send_transaction).
    Pass asset_code + asset_issuer for non-XLM assets; leave None for XLM.
    """
    public_key = load_wallet()
    if not public_key:
        return

    destination = input("Destination public key: ").strip()

    # If no asset specified, offer a menu
    if asset_code is None:
        tracked = load_tracked_assets()
        if tracked:
            print("\nAsset to send:")
            print("  1. XLM (native)")
            for i, a in enumerate(tracked, 2):
                print(f"  {i}. {a['code']}")
            choice = input("Choose asset (default 1): ").strip() or "1"
            if choice != "1":
                idx = int(choice) - 2
                if 0 <= idx < len(tracked):
                    asset_code = tracked[idx]["code"]
                    asset_issuer = tracked[idx]["issuer"]

    asset = Asset(asset_code, asset_issuer) if asset_code else Asset.native()
    asset_label = asset_code if asset_code else "XLM"
    amount = input(f"Amount of {asset_label} to send: ").strip()

    # Extra confirmation on mainnet — real XLM, irreversible
    if NETWORK_NAME == "Mainnet":
        print(f"\n  Network    : {NETWORK_NAME}")
        print(f"  From       : {public_key}")
        print(f"  To         : {destination}")
        print(f"  Amount     : {amount} {asset_label}")
        confirm = input("\n  Type 'send' to confirm this mainnet transaction: ").strip().lower()
        if confirm != "send":
            print("Cancelled.")
            return

    # Decrypt the secret key — this is the only place it ever exists in memory
    secret_key = load_secret()
    if not secret_key:
        return

    try:
        # Load account sequence number via RPC
        source_account = load_account_rpc(public_key)

        # Build the transaction with a single payment operation
        transaction = (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=NETWORK_PASSPHRASE,
                base_fee=100,  # fee in stroops (1 XLM = 10,000,000 stroops)
            )
            .append_payment_op(
                destination=destination,
                asset=asset,
                amount=amount,
            )
            .set_timeout(30)  # transaction expires after 30 seconds
            .build()
        )

        # Sign the transaction envelope with the decrypted secret key
        keypair = Keypair.from_secret(secret_key)
        transaction.sign(keypair)

        # Submit via Stellar RPC
        response = soroban_server.send_transaction(transaction)
        print("\nPayment submitted!")
        print(f"  Transaction hash: {response.hash}")
        print(f"  Status: {response.status}")

    except Exception as e:
        print(f"Error sending payment: {e}")


# ─── Feature: Transaction History ─────────────────────────────────────────────

def view_history():
    """
    Fetch and display the 10 most recent transactions for the loaded wallet.
    Uses Horizon API — Stellar RPC has no account-filtered history endpoint.
    TODO: migrate when Stellar Portfolio APIs are available.
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
    print("║  6. Manage tracked assets║")
    print("║  7. Exit                 ║")
    print("╚══════════════════════════╝")
    return input("Choose an option (1-7): ").strip()


def manage_assets_cli():
    """CLI interface for adding/removing tracked assets."""
    tracked = load_tracked_assets()
    print("\nTracked assets (non-XLM balances to display):")
    if not tracked:
        print("  (none)")
    else:
        for i, a in enumerate(tracked, 1):
            print(f"  {i}. {a['code']}  ({a['issuer']})")

    print("\n  a. Add asset")
    print("  r. Remove asset")
    print("  q. Back to menu")
    choice = input("Choice: ").strip().lower()

    if choice == "a":
        code = input("Asset code (e.g. USDC): ").strip().upper()
        issuer = input("Issuer public key: ").strip()
        if code and issuer:
            add_tracked_asset(code, issuer)
            print(f"Added {code}.")
    elif choice == "r" and tracked:
        num = input("Remove asset number: ").strip()
        try:
            idx = int(num) - 1
            a = tracked[idx]
            remove_tracked_asset(a["code"], a["issuer"])
            print(f"Removed {a['code']}.")
        except (ValueError, IndexError):
            print("Invalid selection.")


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
            manage_assets_cli()
        elif choice == "7":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 7.")


if __name__ == "__main__":
    main()
