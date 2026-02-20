#!/usr/bin/env python3
"""Arroz Wallet — Flask web frontend."""

import json
import os
import requests as http_requests

# Run from the wallet directory so wallet.json is found correctly.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import InvalidToken
from stellar_sdk import Keypair, Server, TransactionBuilder, Asset
from stellar_sdk.exceptions import NotFoundError

import wallet as w

app = Flask(__name__)
# Secret key regenerates on each restart — sessions are lost, but that's fine
# for this localhost tool (only network preference is stored in session).
app.secret_key = os.urandom(24)


# ─── Network Helper ────────────────────────────────────────────────────────────

def get_network_config():
    """Apply the session's network choice to wallet.py globals.

    Returns the network key ("testnet" or "mainnet").
    Called at the start of every route so wallet.py functions use the right server.
    """
    network = session.get("network", "testnet")
    cfg = w.NETWORKS[network]
    w.server = Server(cfg["horizon_url"])
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


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    network = get_network_config()
    public_key = read_public_key()
    balance = None
    error = None

    not_funded = False
    if public_key:
        try:
            account = w.server.accounts().account_id(public_key).call()
            for b in account["balances"]:
                if b.get("asset_type") == "native":
                    balance = b["balance"]
                    break
        except NotFoundError:
            not_funded = True
        except Exception as e:
            error = str(e)

    return render_template(
        "index.html",
        public_key=public_key,
        balance=balance,
        error=error,
        not_funded=not_funded,
        network=network,
        network_name=w.NETWORK_NAME,
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

    if request.method == "POST":
        destination = request.form.get("destination", "").strip()
        amount = request.form.get("amount", "").strip()
        password = request.form.get("password", "")

        if not destination or not amount or not password:
            flash("All fields are required.", "danger")
            return render_template(
                "send.html", network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
            )

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
                public_key=public_key,
            )
        except Exception as e:
            flash(f"Error loading wallet: {e}", "danger")
            return render_template(
                "send.html", network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
            )

        # Build, sign, and submit the transaction.
        try:
            source_account = w.server.load_account(public_key)
            transaction = (
                TransactionBuilder(
                    source_account=source_account,
                    network_passphrase=w.NETWORK_PASSPHRASE,
                    base_fee=100,
                )
                .append_payment_op(
                    destination=destination,
                    asset=Asset.native(),
                    amount=amount,
                )
                .set_timeout(30)
                .build()
            )
            keypair = Keypair.from_secret(secret_key)
            transaction.sign(keypair)
            response = w.server.submit_transaction(transaction)
            flash(f"Payment sent! Transaction hash: {response['hash']}", "success")
            return redirect(url_for("index"))
        except Exception as e:
            flash(f"Error sending payment: {e}", "danger")
            return render_template(
                "send.html", network=network, network_name=w.NETWORK_NAME,
                public_key=public_key,
            )

    return render_template(
        "send.html",
        network=network,
        network_name=w.NETWORK_NAME,
        public_key=public_key,
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
