#!/usr/bin/env python3
"""Arroz Wallet — Flask web frontend."""

import json
import os
import requests as http_requests

# Run from the wallet directory so wallet.json is found correctly.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import InvalidToken
from stellar_sdk import (
    Keypair, Server, SorobanServer, TransactionBuilder,
    TransactionEnvelope, Asset, Account,
)
from stellar_sdk.exceptions import NotFoundError

import wallet as w
import defindex as df
import etherfuse as ef

app = Flask(__name__)
# Secret key regenerates on each restart — sessions are lost, but that's fine
# for this localhost tool (only network preference is stored in session).
app.secret_key = os.urandom(24)


# ─── USDC Issuer ───────────────────────────────────────────────────────────────

_USDC_ISSUERS = {
    # Must match the DeFindex vault asset (USDC:GATALTGTWIOT6BUDBCZM3Q4OQ4BO2COLOAZ7IYSKPLC2PMSOPPGF5V56)
    "testnet": "GATALTGTWIOT6BUDBCZM3Q4OQ4BO2COLOAZ7IYSKPLC2PMSOPPGF5V56",
    "mainnet": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
}

def _usdc_issuer(network: str) -> str:
    return _USDC_ISSUERS.get(network, _USDC_ISSUERS["testnet"])


# ─── Swap Rate Helper ──────────────────────────────────────────────────────────

def _get_swap_record(send_asset, dest_asset, send_amount):
    """Query Horizon strict-send paths. Returns the best path record dict or None."""
    try:
        result = w.server.strict_send_paths(
            source_asset=send_asset,
            source_amount=send_amount,
            destination=[dest_asset],
        ).call()
        records = result.get("_embedded", {}).get("records", [])
        if records:
            return records[0]
    except Exception:
        pass
    return None


def _get_swap_rate(send_asset, dest_asset, send_amount):
    """Query Horizon strict-send paths. Returns float dest amount or None."""
    record = _get_swap_record(send_asset, dest_asset, send_amount)
    if record:
        return float(record["destination_amount"])
    return None


def _path_from_record(record):
    """Extract intermediate Asset list from a Horizon path record."""
    path = []
    for hop in record.get("path", []):
        if hop["asset_type"] == "native":
            path.append(Asset.native())
        else:
            path.append(Asset(hop["asset_code"], hop["asset_issuer"]))
    return path


# ─── Network Helper ────────────────────────────────────────────────────────────

def get_network_config():
    """Apply the session's network choice to wallet.py globals.

    Returns the network key ("testnet" or "mainnet").
    Called at the start of every route so wallet.py functions use the right server.
    """
    network = session.get("network", "testnet")
    cfg = w.NETWORKS[network]
    # TODO: Remove Horizon server when history is migrated to Stellar Portfolio APIs
    w.server = Server(cfg["horizon_url"])
    w.soroban_server = SorobanServer(cfg["rpc_url"])
    w.NETWORK_PASSPHRASE = cfg["passphrase"]
    w.NETWORK_NAME = cfg["name"]
    w.FRIENDBOT_URL = cfg["friendbot_url"]
    return network


def read_public_key():
    """Read the public key directly from wallet.json without printing."""
    if not os.path.exists(w.WALLET_FILE):
        return None
    with open(w.WALLET_FILE, "r") as f:
        data = json.load(f)
    return data.get("public_key")


# ─── DeFindex Helper ───────────────────────────────────────────────────────────

def _sign_and_submit_xdr(unsigned_xdr, password, public_key):
    """Decrypt wallet secret, sign the DeFindex-provided XDR, submit via RPC."""
    with open(w.WALLET_FILE) as f:
        data = json.load(f)
    secret_key = w._decrypt_secret(data["encrypted_secret"], data["salt"], password)
    te = TransactionEnvelope.from_xdr(unsigned_xdr, w.NETWORK_PASSPHRASE)
    te.sign(Keypair.from_secret(secret_key))
    return w.soroban_server.send_transaction(te)


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    network = get_network_config()
    public_key = read_public_key()
    balances = []
    error = None
    not_funded = False

    if public_key:
        try:
            balances = w.get_all_balances(public_key)
            if not balances:
                not_funded = True
        except Exception as e:
            error = str(e)

    vault_info, vault_balance, vault_error = None, None, None
    if df.is_configured() and public_key and not not_funded:
        try:
            vault_info = df.get_vault_info(network)
        except Exception as e:
            vault_error = str(e)
        try:
            vault_balance = df.get_vault_balance(network, public_key)
        except Exception as e:
            vault_error = vault_error or str(e)

    return render_template(
        "index.html",
        public_key=public_key,
        balances=balances,
        error=error,
        not_funded=not_funded,
        network=network,
        network_name=w.NETWORK_NAME,
        vault_info=vault_info,
        vault_balance=vault_balance,
        vault_error=vault_error,
        vault_configured=df.is_configured(),
    )


@app.route("/create", methods=["GET", "POST"])
def create():
    network = get_network_config()
    wallet_exists = os.path.exists(w.WALLET_FILE)

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        overwrite = request.form.get("overwrite", "")

        if not password:
            flash("Password is required.", "danger")
            return render_template(
                "create.html", network=network, network_name=w.NETWORK_NAME,
                wallet_exists=wallet_exists,
            )

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template(
                "create.html", network=network, network_name=w.NETWORK_NAME,
                wallet_exists=wallet_exists,
            )

        if wallet_exists and overwrite != "yes":
            flash(
                "Check the confirmation box to overwrite your existing wallet.",
                "danger",
            )
            return render_template(
                "create.html", network=network, network_name=w.NETWORK_NAME,
                wallet_exists=wallet_exists,
            )

        # Generate a fresh keypair and save it encrypted.
        keypair = Keypair.random()
        w.save_wallet(keypair.public_key, keypair.secret, password)

        if w.FRIENDBOT_URL:
            try:
                resp = http_requests.get(
                    w.FRIENDBOT_URL,
                    params={"addr": keypair.public_key},
                    timeout=15,
                )
                if resp.status_code == 200:
                    flash(
                        "Wallet created and funded with 10,000 testnet XLM!",
                        "success",
                    )
                else:
                    flash(
                        f"Wallet created! Friendbot returned {resp.status_code}.",
                        "warning",
                    )
            except Exception as e:
                flash(f"Wallet created! Could not contact Friendbot: {e}", "warning")
        else:
            flash(
                f"Wallet created! Fund it by sending XLM to: {keypair.public_key}",
                "success",
            )

        return redirect(url_for("index"))

    return render_template(
        "create.html",
        network=network,
        network_name=w.NETWORK_NAME,
        wallet_exists=wallet_exists,
    )


@app.route("/send", methods=["GET", "POST"])
def send():
    network = get_network_config()

    if not os.path.exists(w.WALLET_FILE):
        flash("No wallet found. Please create one first.", "warning")
        return redirect(url_for("create"))

    public_key = read_public_key()
    tracked_assets = w.load_tracked_assets()

    if request.method == "POST":
        destination = request.form.get("destination", "").strip()
        amount = request.form.get("amount", "").strip()
        password = request.form.get("password", "")
        # "native" or "CODE:ISSUER"
        asset_value = request.form.get("asset", "native")

        if not destination or not amount or not password:
            flash("All fields are required.", "danger")
            return render_template(
                "send.html", network=network, network_name=w.NETWORK_NAME,
                public_key=public_key, tracked_assets=tracked_assets,
            )

        # Parse the asset selection
        if asset_value == "native":
            asset = Asset.native()
        else:
            code, issuer = asset_value.split(":", 1)
            asset = Asset(code, issuer)

        # Decrypt the secret key — password is never stored anywhere.
        try:
            with open(w.WALLET_FILE, "r") as f:
                data = json.load(f)
            secret_key = w._decrypt_secret(
                data["encrypted_secret"], data["salt"], password
            )
        except InvalidToken:
            flash("Incorrect password.", "danger")
            return render_template(
                "send.html", network=network, network_name=w.NETWORK_NAME,
                public_key=public_key, tracked_assets=tracked_assets,
            )
        except Exception as e:
            flash(f"Error loading wallet: {e}", "danger")
            return render_template(
                "send.html", network=network, network_name=w.NETWORK_NAME,
                public_key=public_key, tracked_assets=tracked_assets,
            )

        # Build, sign, and submit via Stellar RPC.
        try:
            source_account = w.load_account_rpc(public_key)
            transaction = (
                TransactionBuilder(
                    source_account=source_account,
                    network_passphrase=w.NETWORK_PASSPHRASE,
                    base_fee=100,
                )
                .append_payment_op(
                    destination=destination,
                    asset=asset,
                    amount=amount,
                )
                .set_timeout(30)
                .build()
            )
            keypair = Keypair.from_secret(secret_key)
            transaction.sign(keypair)
            response = w.soroban_server.send_transaction(transaction)
            if response.status == "ERROR":
                flash(f"Transaction failed: {response.error_result_xdr}", "danger")
            else:
                flash(
                    f"Payment sent! Transaction hash: {response.hash}",
                    "success",
                )
                return redirect(url_for("index"))
        except Exception as e:
            flash(f"Error sending payment: {e}", "danger")

        return render_template(
            "send.html", network=network, network_name=w.NETWORK_NAME,
            public_key=public_key, tracked_assets=tracked_assets,
        )

    return render_template(
        "send.html",
        network=network,
        network_name=w.NETWORK_NAME,
        public_key=public_key,
        tracked_assets=tracked_assets,
    )


@app.route("/assets", methods=["GET", "POST"])
def assets():
    network = get_network_config()

    if not os.path.exists(w.WALLET_FILE):
        flash("No wallet found. Please create one first.", "warning")
        return redirect(url_for("create"))

    if request.method == "POST":
        action = request.form.get("action")
        code = request.form.get("code", "").strip().upper()
        issuer = request.form.get("issuer", "").strip()

        if action == "add":
            if not code or not issuer:
                flash("Asset code and issuer address are both required.", "danger")
            else:
                w.add_tracked_asset(code, issuer)
                flash(f"{code} added to tracked assets.", "success")
        elif action == "remove":
            w.remove_tracked_asset(code, issuer)
            flash(f"{code} removed from tracked assets.", "success")
        elif action == "trustline":
            password = request.form.get("password", "")
            if not code or not issuer or not password:
                flash("Asset code, issuer address, and password are all required.", "danger")
                tracked = w.load_tracked_assets()
                return render_template(
                    "assets.html", tracked_assets=tracked,
                    network=network, network_name=w.NETWORK_NAME,
                )
            try:
                with open(w.WALLET_FILE) as f:
                    data = json.load(f)
                secret_key = w._decrypt_secret(data["encrypted_secret"], data["salt"], password)
            except InvalidToken:
                flash("Incorrect password.", "danger")
                tracked = w.load_tracked_assets()
                return render_template(
                    "assets.html", tracked_assets=tracked,
                    network=network, network_name=w.NETWORK_NAME,
                )
            except Exception as e:
                flash(f"Error loading wallet: {e}", "danger")
                tracked = w.load_tracked_assets()
                return render_template(
                    "assets.html", tracked_assets=tracked,
                    network=network, network_name=w.NETWORK_NAME,
                )
            try:
                public_key = read_public_key()
                source_account = w.load_account_rpc(public_key)
                transaction = (
                    TransactionBuilder(
                        source_account=source_account,
                        network_passphrase=w.NETWORK_PASSPHRASE,
                        base_fee=100,
                    )
                    .append_change_trust_op(asset=Asset(code, issuer))
                    .set_timeout(30)
                    .build()
                )
                transaction.sign(Keypair.from_secret(secret_key))
                response = w.soroban_server.send_transaction(transaction)
                if response.status == "ERROR":
                    flash(f"Trustline failed: {response.error_result_xdr}", "danger")
                else:
                    w.add_tracked_asset(code, issuer)
                    flash(f"Trustline created for {code}! Transaction hash: {response.hash}", "success")
            except Exception as e:
                flash(f"Error creating trustline: {e}", "danger")

        return redirect(url_for("assets"))

    tracked = w.load_tracked_assets()
    return render_template(
        "assets.html",
        tracked_assets=tracked,
        network=network,
        network_name=w.NETWORK_NAME,
    )


@app.route("/history")
def history():
    network = get_network_config()

    if not os.path.exists(w.WALLET_FILE):
        flash("No wallet found. Please create one first.", "warning")
        return redirect(url_for("create"))

    public_key = read_public_key()
    transactions = []
    error = None

    # TODO: migrate to Stellar Portfolio APIs when available.
    # Stellar RPC has no account-filtered history endpoint; Horizon is kept for this.
    try:
        response = (
            w.server.transactions()
            .for_account(public_key)
            .limit(10)
            .order(desc=True)
            .call()
        )
        transactions = response["_embedded"]["records"]
    except Exception as e:
        error = str(e)

    return render_template(
        "history.html",
        public_key=public_key,
        transactions=transactions,
        error=error,
        network=network,
        network_name=w.NETWORK_NAME,
    )


@app.route("/fund", methods=["POST"])
def fund():
    get_network_config()
    if not w.FRIENDBOT_URL:
        flash("Friendbot is only available on testnet.", "warning")
        return redirect(url_for("index"))

    public_key = read_public_key()
    if not public_key:
        flash("No wallet found.", "warning")
        return redirect(url_for("create"))

    try:
        resp = http_requests.get(
            w.FRIENDBOT_URL, params={"addr": public_key}, timeout=15
        )
        if resp.status_code == 200:
            flash("Account funded with 10,000 testnet XLM!", "success")
        else:
            data = resp.json()
            detail = data.get("detail", resp.text)
            flash(f"Friendbot error: {detail}", "danger")
    except Exception as e:
        flash(f"Could not contact Friendbot: {e}", "danger")

    return redirect(url_for("index"))


@app.route("/vault", methods=["GET", "POST"])
def vault():
    network = get_network_config()

    if not df.is_configured():
        flash("DeFindex is not configured. Add defindex.json to enable vault features.", "warning")
        return redirect(url_for("index"))

    if not os.path.exists(w.WALLET_FILE):
        flash("No wallet found. Please create one first.", "warning")
        return redirect(url_for("create"))

    public_key = read_public_key()
    vault_info, vault_balance, vault_error = None, None, None

    try:
        vault_info = df.get_vault_info(network)
    except Exception as e:
        vault_error = str(e)
    try:
        vault_balance = df.get_vault_balance(network, public_key)
    except Exception as e:
        vault_error = vault_error or str(e)

    if request.method == "POST":
        action = request.form.get("action", "").strip()
        amount = request.form.get("amount", "").strip()
        password = request.form.get("password", "")

        if action not in ("deposit", "withdraw") or not amount or not password:
            flash("Action, amount, and password are all required.", "danger")
            return render_template(
                "vault.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                vault_info=vault_info, vault_balance=vault_balance,
                vault_error=vault_error,
                vault_address=df.get_vault_address(network),
                form_amount=amount, form_action=action,
            )

        try:
            stroops = df.decimal_to_stroops(amount)
        except (ValueError, TypeError) as e:
            flash(f"Invalid amount: {e}", "danger")
            return render_template(
                "vault.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                vault_info=vault_info, vault_balance=vault_balance,
                vault_error=vault_error,
                vault_address=df.get_vault_address(network),
                form_amount=amount, form_action=action,
            )

        try:
            if action == "deposit":
                unsigned_xdr = df.build_deposit_xdr(network, public_key, stroops)
            else:
                unsigned_xdr = df.build_withdraw_xdr(network, public_key, stroops)
        except Exception as e:
            flash(f"DeFindex API error: {e}", "danger")
            return render_template(
                "vault.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                vault_info=vault_info, vault_balance=vault_balance,
                vault_error=vault_error,
                vault_address=df.get_vault_address(network),
                form_amount=amount, form_action=action,
            )

        try:
            response = _sign_and_submit_xdr(unsigned_xdr, password, public_key)
        except InvalidToken:
            flash("Incorrect password.", "danger")
            return render_template(
                "vault.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                vault_info=vault_info, vault_balance=vault_balance,
                vault_error=vault_error,
                vault_address=df.get_vault_address(network),
                form_amount=amount, form_action=action,
            )
        except Exception as e:
            flash(f"Error submitting transaction: {e}", "danger")
            return render_template(
                "vault.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                vault_info=vault_info, vault_balance=vault_balance,
                vault_error=vault_error,
                vault_address=df.get_vault_address(network),
                form_amount=amount, form_action=action,
            )

        if response.status == "ERROR":
            flash(f"Transaction failed: {response.error_result_xdr}", "danger")
            return render_template(
                "vault.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                vault_info=vault_info, vault_balance=vault_balance,
                vault_error=vault_error,
                vault_address=df.get_vault_address(network),
                form_amount=amount, form_action=action,
            )

        flash(f"{action.capitalize()} submitted! Transaction hash: {response.hash}", "success")
        return redirect(url_for("vault"))

    return render_template(
        "vault.html",
        network=network, network_name=w.NETWORK_NAME,
        public_key=public_key,
        vault_info=vault_info, vault_balance=vault_balance,
        vault_error=vault_error,
        vault_address=df.get_vault_address(network),
        form_amount=None, form_action=None,
    )


@app.route("/ramp", methods=["GET", "POST"])
def ramp():
    network = get_network_config()

    if not ef.is_configured():
        flash("Etherfuse is not configured. Add etherfuse.json to enable ramp features.", "warning")
        return redirect(url_for("index"))

    if not os.path.exists(w.WALLET_FILE):
        flash("No wallet found. Please create one first.", "warning")
        return redirect(url_for("create"))

    # Auto-generate customer_id if still placeholder
    ef.ensure_customer_id()

    public_key = read_public_key()
    exchange_rates = None
    recent_orders = []

    try:
        exchange_rates = ef.get_exchange_rates(network)
    except Exception:
        pass

    if ef.is_ready():
        try:
            recent_orders = ef.list_orders(network=network)
        except Exception:
            pass

    if request.method == "POST":
        action = request.form.get("action", "").strip()
        amount = request.form.get("amount", "").strip()
        password = request.form.get("password", "")

        if action not in ("onramp", "offramp") or not amount:
            flash("Action and amount are required.", "danger")
            return render_template(
                "ramp.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                exchange_rates=exchange_rates,
                recent_orders=recent_orders,
                ef_configured=ef.is_configured(),
                ef_ready=ef.is_ready(),
                form_amount=amount, form_action=action,
            )

        if action == "offramp" and not password:
            flash("Password is required for off-ramp.", "danger")
            return render_template(
                "ramp.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                exchange_rates=exchange_rates,
                recent_orders=recent_orders,
                ef_configured=ef.is_configured(),
                ef_ready=ef.is_ready(),
                form_amount=amount, form_action=action,
            )

        order_id = ef.new_order_id()

        try:
            quote = ef.get_quote(action, amount, public_key, network=network)
        except Exception as e:
            flash(f"Quote error: {e}", "danger")
            return render_template(
                "ramp.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                exchange_rates=exchange_rates,
                recent_orders=recent_orders,
                ef_configured=ef.is_configured(),
                ef_ready=ef.is_ready(),
                form_amount=amount, form_action=action,
            )

        try:
            order = ef.create_order(order_id, quote["quoteId"], action, public_key, amount, network=network)
        except Exception as e:
            flash(f"Order error: {e}", "danger")
            return render_template(
                "ramp.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                exchange_rates=exchange_rates,
                recent_orders=recent_orders,
                ef_configured=ef.is_configured(),
                ef_ready=ef.is_ready(),
                form_amount=amount, form_action=action,
            )

        if action == "offramp":
            try:
                offramp_data = order.get("offramp", order)
                actual_order_id = offramp_data.get("orderId", order_id)
                if "xdr" in order:
                    response = _sign_and_submit_xdr(order["xdr"], password, public_key)
                    if response.status == "ERROR":
                        flash(f"Transaction failed: {response.error_result_xdr}", "danger")
                        return render_template(
                            "ramp.html",
                            network=network, network_name=w.NETWORK_NAME,
                            public_key=public_key,
                            exchange_rates=exchange_rates,
                            recent_orders=recent_orders,
                            ef_configured=ef.is_configured(),
                            ef_ready=ef.is_ready(),
                            form_amount=amount, form_action=action,
                        )
                else:
                    # Off-ramp: send CETES back to the issuer (burns them).
                    # Etherfuse matches the payment to the pending order by
                    # wallet public key and credits MXN to the bank account.
                    deposit_address = order.get("depositAddress", ef.cetes_issuer(network))
                    memo = order.get("memo", actual_order_id)
                    with open(w.WALLET_FILE) as f:
                        data = json.load(f)
                    secret_key = w._decrypt_secret(data["encrypted_secret"], data["salt"], password)
                    source_account = w.load_account_rpc(public_key)
                    cetes_asset = Asset("CETES", ef.cetes_issuer(network))
                    builder = TransactionBuilder(
                        source_account=source_account,
                        network_passphrase=w.NETWORK_PASSPHRASE,
                        base_fee=100,
                    ).append_payment_op(
                        destination=deposit_address,
                        asset=cetes_asset,
                        amount=amount,
                    ).set_timeout(30)
                    from stellar_sdk import TextMemo
                    builder.add_text_memo(memo[:28])  # Stellar memo limit: 28 bytes
                    transaction = builder.build()
                    transaction.sign(Keypair.from_secret(secret_key))
                    response = w.soroban_server.send_transaction(transaction)
                    if response.status == "ERROR":
                        flash(f"Transaction failed: {response.error_result_xdr}", "danger")
                        return render_template(
                            "ramp.html",
                            network=network, network_name=w.NETWORK_NAME,
                            public_key=public_key,
                            exchange_rates=exchange_rates,
                            recent_orders=recent_orders,
                            ef_configured=ef.is_configured(),
                            ef_ready=ef.is_ready(),
                            form_amount=amount, form_action=action,
                        )
            except InvalidToken:
                flash("Incorrect password.", "danger")
                return render_template(
                    "ramp.html",
                    network=network, network_name=w.NETWORK_NAME,
                    public_key=public_key,
                    exchange_rates=exchange_rates,
                    recent_orders=recent_orders,
                    ef_configured=ef.is_configured(),
                    ef_ready=ef.is_ready(),
                    form_amount=amount, form_action=action,
                )
            except Exception as e:
                flash(f"Error submitting transaction: {e}", "danger")
                return render_template(
                    "ramp.html",
                    network=network, network_name=w.NETWORK_NAME,
                    public_key=public_key,
                    exchange_rates=exchange_rates,
                    recent_orders=recent_orders,
                    ef_configured=ef.is_configured(),
                    ef_ready=ef.is_ready(),
                    form_amount=amount, form_action=action,
                )

        status = order.get("status", "pending")
        if action == "onramp" and network == "testnet":
            session["last_onramp_order_id"] = order_id
        flash(f"Order created! ID: {order_id[:8]}... Status: {status}", "success")
        return redirect(url_for("ramp"))

    last_onramp_id = session.get("last_onramp_order_id") if network == "testnet" else None
    # Clear it if it already appears as completed in the list
    if last_onramp_id:
        for o in recent_orders:
            if (o.get("orderId") or o.get("id")) == last_onramp_id and o.get("status") == "completed":
                session.pop("last_onramp_order_id", None)
                last_onramp_id = None
                break

    return render_template(
        "ramp.html",
        network=network, network_name=w.NETWORK_NAME,
        public_key=public_key,
        exchange_rates=exchange_rates,
        recent_orders=recent_orders,
        ef_configured=ef.is_configured(),
        ef_ready=ef.is_ready(),
        form_amount=None, form_action=None,
        last_onramp_order_id=last_onramp_id,
    )


@app.route("/ramp/simulate", methods=["POST"])
def ramp_simulate():
    network = get_network_config()

    if network != "testnet":
        flash("Simulate is only available on testnet.", "warning")
        return redirect(url_for("ramp"))

    if not ef.is_configured():
        flash("Etherfuse is not configured.", "warning")
        return redirect(url_for("index"))

    order_id = request.form.get("order_id", "").strip()
    if not order_id:
        flash("Missing order ID.", "danger")
        return redirect(url_for("ramp"))

    try:
        ef.simulate_fiat_received(order_id, network=network)
        session.pop("last_onramp_order_id", None)
        flash("Bank payment simulated — order should move to completed shortly. Refresh to see updated status.", "success")
    except Exception as e:
        flash(f"Simulation error: {e}", "danger")

    return redirect(url_for("ramp"))


@app.route("/ramp/setup", methods=["POST"])
def ramp_setup():
    get_network_config()

    if not ef.is_configured():
        flash("Etherfuse is not configured.", "warning")
        return redirect(url_for("index"))

    public_key = read_public_key()
    if not public_key:
        flash("No wallet found. Please create one first.", "warning")
        return redirect(url_for("create"))

    ef.ensure_customer_id()

    network = session.get("network", "testnet")
    try:
        url = ef.get_onboarding_url(public_key, network=network)
        if url:
            return redirect(url)
        flash("Could not retrieve onboarding URL from Etherfuse.", "danger")
    except Exception as e:
        flash(f"Onboarding URL error: {e}", "danger")

    return redirect(url_for("ramp"))


@app.route("/swap", methods=["GET", "POST"])
def swap():
    network = get_network_config()

    if not os.path.exists(w.WALLET_FILE):
        flash("No wallet found. Please create one first.", "warning")
        return redirect(url_for("create"))

    public_key = read_public_key()
    cetes = Asset("CETES", ef.cetes_issuer(network))
    usdc = Asset("USDC", _usdc_issuer(network))

    cetes_to_usdc = _get_swap_rate(cetes, usdc, "1")
    usdc_to_cetes = _get_swap_rate(usdc, cetes, "1")

    if request.method == "POST":
        direction = request.form.get("direction", "").strip()
        amount = request.form.get("amount", "").strip()
        password = request.form.get("password", "")

        def _rerender():
            return render_template(
                "swap.html",
                network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
                cetes_to_usdc=cetes_to_usdc,
                usdc_to_cetes=usdc_to_cetes,
                cetes_issuer=ef.cetes_issuer(network),
                usdc_issuer=_usdc_issuer(network),
                form_direction=direction,
                form_amount=amount,
            )

        if direction not in ("cetes_to_usdc", "usdc_to_cetes") or not amount or not password:
            flash("Direction, amount, and password are all required.", "danger")
            return _rerender()

        if direction == "cetes_to_usdc":
            send_asset, dest_asset = cetes, usdc
            send_label, dest_label = "CETES", "USDC"
        else:
            send_asset, dest_asset = usdc, cetes
            send_label, dest_label = "USDC", "CETES"

        record = _get_swap_record(send_asset, dest_asset, amount)
        if record is None:
            flash("No liquidity found for this swap.", "danger")
            return _rerender()

        expected = float(record["destination_amount"])
        dest_min = f"{expected * 0.99:.7f}"
        hop_path = _path_from_record(record)

        try:
            with open(w.WALLET_FILE) as f:
                data = json.load(f)
            secret_key = w._decrypt_secret(data["encrypted_secret"], data["salt"], password)
        except InvalidToken:
            flash("Incorrect password.", "danger")
            return _rerender()
        except Exception as e:
            flash(f"Error loading wallet: {e}", "danger")
            return _rerender()

        try:
            source_account = w.load_account_rpc(public_key)
            transaction = (
                TransactionBuilder(
                    source_account=source_account,
                    network_passphrase=w.NETWORK_PASSPHRASE,
                    base_fee=100,
                )
                .append_path_payment_strict_send_op(
                    destination=public_key,
                    send_asset=send_asset,
                    send_amount=amount,
                    dest_asset=dest_asset,
                    dest_min=dest_min,
                    path=hop_path,
                )
                .set_timeout(30)
                .build()
            )
            transaction.sign(Keypair.from_secret(secret_key))
            response = w.soroban_server.send_transaction(transaction)
        except Exception as e:
            flash(f"Error submitting transaction: {e}", "danger")
            return _rerender()

        if response.status == "ERROR":
            flash(f"Transaction failed: {response.error_result_xdr}", "danger")
            return _rerender()

        flash(
            f"Swapped {amount} {send_label} → ~{float(dest_min):.4f} {dest_label} (tx pending)",
            "success",
        )
        return redirect(url_for("swap"))

    return render_template(
        "swap.html",
        network=network, network_name=w.NETWORK_NAME,
        public_key=public_key,
        cetes_to_usdc=cetes_to_usdc,
        usdc_to_cetes=usdc_to_cetes,
        cetes_issuer=ef.cetes_issuer(network),
        usdc_issuer=_usdc_issuer(network),
        form_direction=None,
        form_amount=None,
    )


@app.route("/network", methods=["POST"])
def set_network():
    network = request.form.get("network", "testnet")
    if network in w.NETWORKS:
        session["network"] = network
    return redirect(request.referrer or url_for("index"))


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting Arroz Wallet web interface...")
    print("Open http://localhost:5001 in your browser.")
    app.run(debug=True, port=5001)
