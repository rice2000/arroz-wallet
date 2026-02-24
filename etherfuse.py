#!/usr/bin/env python3
"""Etherfuse Ramp API client for Arroz Wallet."""

import json
import uuid

import requests

_CONFIG_FILE = "etherfuse.json"
_BASE_URL = "https://api.etherfuse.com"

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


def _headers() -> dict:
    return {"Authorization": _cfg["api_key"], "Content-Type": "application/json"}


def new_order_id() -> str:
    return str(uuid.uuid4())


def get_exchange_rates() -> dict:
    """GET /ramp/exchange-rates."""
    resp = requests.get(f"{_BASE_URL}/ramp/exchange-rates", headers=_headers(), timeout=15)
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/exchange-rates returned {resp.status_code}: {resp.text}")
    return resp.json()


def get_quote(direction: str, amount: str, public_key: str, blockchain: str = "stellar") -> dict:
    """POST /ramp/quote — returns dict including quoteId and rate info."""
    body = {
        "direction": direction,
        "amount": amount,
        "publicKey": public_key,
        "blockchain": blockchain,
    }
    resp = requests.post(f"{_BASE_URL}/ramp/quote", headers=_headers(), json=body, timeout=15)
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/quote returned {resp.status_code}: {resp.text}")
    return resp.json()


def create_order(
    order_id: str,
    quote_id: str,
    direction: str,
    public_key: str,
    amount: str,
    blockchain: str = "stellar",
) -> dict:
    """POST /ramp/order — create an on-ramp or off-ramp order."""
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
    resp = requests.post(f"{_BASE_URL}/ramp/order", headers=_headers(), json=body, timeout=15)
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/order returned {resp.status_code}: {resp.text}")
    return resp.json()


def list_orders(page_size: int = 5, page_number: int = 1) -> list:
    """POST /ramp/orders — returns a list of recent orders."""
    body = {"pageSize": page_size, "pageNumber": page_number}
    resp = requests.post(f"{_BASE_URL}/ramp/orders", headers=_headers(), json=body, timeout=15)
    if resp.status_code != 200:
        raise ValueError(f"Etherfuse /ramp/orders returned {resp.status_code}: {resp.text}")
    data = resp.json()
    # API may return {"orders": [...]} or a bare list
    if isinstance(data, list):
        return data
    return data.get("orders", data.get("data", []))


def get_onboarding_url(public_key: str) -> str:
    """POST /ramp/onboarding-url — returns presigned URL for KYC/bank setup."""
    body = {
        "customerId": _cfg["customer_id"],
        "bankAccountId": _cfg.get("bank_account_id", ""),
        "publicKey": public_key,
        "blockchain": "stellar",
    }
    resp = requests.post(
        f"{_BASE_URL}/ramp/onboarding-url", headers=_headers(), json=body, timeout=15
    )
    if resp.status_code != 200:
        raise ValueError(
            f"Etherfuse /ramp/onboarding-url returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return data.get("presigned_url") or data.get("url") or data.get("onboardingUrl", "")


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
