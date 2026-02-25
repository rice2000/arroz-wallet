#!/usr/bin/env python3
"""Etherfuse Ramp API client for Arroz Wallet."""

import json
import uuid

import requests

_CONFIG_FILE = "etherfuse.json"

# Network-aware base URLs (testnet uses the sandbox API)
_BASE_URLS = {
    "testnet": "https://api.sand.etherfuse.com",
    "mainnet": "https://api.etherfuse.com",
}

# Sandbox CETES issuer on Stellar testnet
# Mainnet issuer: GCRYUGD5NVARGXT56XEZI5CIFCQETYHAPQQTHO2O3IQZTHDH4LATMYWC
_CETES_ISSUERS = {
    "testnet": "GC3CW7EDYRTWQ635VDIGY6S4ZUF5L6TQ7AA4MWS7LEQDBLUSZXV7UPS4",
    "mainnet": "GCRYUGD5NVARGXT56XEZI5CIFCQETYHAPQQTHO2O3IQZTHDH4LATMYWC",
}

_PLACEHOLDER = "uuid-from-etherfuse-dashboard"

# Load config at import time; degrade gracefully if file is missing.
try:
    with open(_CONFIG_FILE) as _f:
        _cfg = json.load(_f)
    _CONFIGURED = True
except (FileNotFoundError, KeyError, json.JSONDecodeError):
    _cfg = {}
    _CONFIGURED = False


def is_configured() -> bool:
    """Return True if etherfuse.json exists and was loaded successfully."""
    return _CONFIGURED


def is_ready() -> bool:
    """Return True when api_key, customer_id, and bank_account_id are all real values."""
    if not _CONFIGURED:
        return False
    return (
        bool(_cfg.get("api_key"))
        and _cfg.get("customer_id", _PLACEHOLDER) != _PLACEHOLDER
        and bool(_cfg.get("customer_id"))
        and _cfg.get("bank_account_id", _PLACEHOLDER) != _PLACEHOLDER
        and bool(_cfg.get("bank_account_id"))
    )


def _base_url(network: str = "testnet") -> str:
    return _BASE_URLS.get(network, _BASE_URLS["testnet"])


def cetes_issuer(network: str = "testnet") -> str:
    return _CETES_ISSUERS.get(network, _CETES_ISSUERS["testnet"])


def _headers() -> dict:
    return {"Authorization": _cfg["api_key"], "Content-Type": "application/json"}


def new_order_id() -> str:
    return str(uuid.uuid4())


def get_exchange_rates(network: str = "testnet") -> dict:
    """GET /ramp/assets — returns available assets and rates."""
    resp = requests.get(
        f"{_base_url(network)}/ramp/assets",
        headers=_headers(),
        params={"blockchain": "stellar"},
        timeout=15,
    )
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/assets returned {resp.status_code}: {resp.text}")
    return resp.json()


def get_quote(direction: str, amount: str, public_key: str, network: str = "testnet", blockchain: str = "stellar") -> dict:
    """POST /ramp/quote — returns quote including quoteId, exchangeRate, destinationAmountAfterFee.

    quoteAssets format confirmed from sandbox testing:
      {"type": "onramp"|"offramp", "sourceAsset": "<CODE>", "targetAsset": "<CODE:ISSUER>"}
    For onramp: sourceAsset="MXN", targetAsset="CETES:<issuer>"
    For offramp: sourceAsset="CETES:<issuer>", targetAsset="MXN"
    """
    issuer = cetes_issuer(network)
    if direction == "onramp":
        quote_assets = {"type": "onramp", "sourceAsset": "MXN", "targetAsset": f"CETES:{issuer}"}
    else:
        quote_assets = {"type": "offramp", "sourceAsset": f"CETES:{issuer}", "targetAsset": "MXN"}

    body = {
        "quoteId": new_order_id(),
        "customerId": _cfg["customer_id"],
        "publicKey": public_key,
        "blockchain": blockchain,
        "sourceAmount": amount,
        "quoteAssets": quote_assets,
    }
    resp = requests.post(f"{_base_url(network)}/ramp/quote", headers=_headers(), json=body, timeout=15)
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/quote returned {resp.status_code}: {resp.text}")
    return resp.json()


def create_order(
    order_id: str,
    quote_id: str,
    direction: str,
    public_key: str,
    amount: str,
    network: str = "testnet",
    blockchain: str = "stellar",
) -> dict:
    """POST /ramp/order — create an on-ramp or off-ramp order.

    Requires a quoteId from a prior call to get_quote().
    fiatAmount used for onramp; tokenAmount for offramp.
    """
    body = {
        "orderId": order_id,
        "quoteId": quote_id,
        "direction": direction,
        "publicKey": public_key,
        "blockchain": blockchain,
        "bankAccountId": _cfg["bank_account_id"],
        "customerId": _cfg["customer_id"],
    }
    if direction == "onramp":
        body["fiatAmount"] = amount
    else:
        body["tokenAmount"] = amount
    resp = requests.post(f"{_base_url(network)}/ramp/order", headers=_headers(), json=body, timeout=15)
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/order returned {resp.status_code}: {resp.text}")
    return resp.json()


def list_orders(page_size: int = 5, page_number: int = 0, network: str = "testnet") -> list:
    """POST /ramp/orders — returns a list of recent orders. Page numbers are 0-indexed."""
    body = {"pageSize": page_size, "pageNumber": page_number}
    resp = requests.post(f"{_base_url(network)}/ramp/orders", headers=_headers(), json=body, timeout=15)
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/orders returned {resp.status_code}: {resp.text}")
    data = resp.json()
    if isinstance(data, list):
        return data
    return data.get("items", data.get("orders", data.get("data", [])))


def get_onboarding_url(public_key: str, network: str = "testnet") -> str:
    """POST /ramp/onboarding-url — returns presigned URL for KYC/T&C/bank setup."""
    body = {
        "customerId": _cfg["customer_id"],
        "bankAccountId": _cfg.get("bank_account_id", ""),
        "publicKey": public_key,
        "blockchain": "stellar",
    }
    resp = requests.post(
        f"{_base_url(network)}/ramp/onboarding-url", headers=_headers(), json=body, timeout=15
    )
    if resp.status_code != 200:
        raise ValueError(
            f"Etherfuse /ramp/onboarding-url returned {resp.status_code}: {resp.text}"
        )
    return resp.json().get("presigned_url", "")


def simulate_fiat_received(order_id: str, network: str = "testnet") -> dict:
    """POST /ramp/order/fiat_received — sandbox only. Simulates MXN bank transfer arriving,
    progressing the order from pending → funded → completed and minting CETES."""
    resp = requests.post(
        f"{_base_url(network)}/ramp/order/fiat_received",
        headers=_headers(),
        json={"orderId": order_id},
        timeout=15,
    )
    if resp.status_code not in (200, 201, 204):
        raise ValueError(f"fiat_received returned {resp.status_code}: {resp.text}")
    return resp.json() if resp.content else {}


def ensure_customer_id() -> bool:
    """Auto-generate and persist a customer_id if it's still a placeholder. Returns True if changed."""
    global _cfg
    if not _CONFIGURED:
        return False
    if _cfg.get("customer_id", _PLACEHOLDER) == _PLACEHOLDER:
        _cfg["customer_id"] = str(uuid.uuid4())
        with open(_CONFIG_FILE, "w") as f:
            json.dump(_cfg, f, indent=2)
            f.write("\n")
        return True
    return False
