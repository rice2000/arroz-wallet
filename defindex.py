#!/usr/bin/env python3
"""DeFindex REST API client for Arroz Wallet."""

import json
import os

import requests

_CONFIG_FILE = "defindex.json"
_BASE_URL = "https://api.defindex.io"

# Load config at import time; degrade gracefully if file is missing.
try:
    with open(_CONFIG_FILE) as _f:
        _cfg = json.load(_f)
    _CONFIGURED = True
except (FileNotFoundError, KeyError, json.JSONDecodeError):
    _cfg = {}
    _CONFIGURED = False


def is_configured() -> bool:
    return _CONFIGURED


def get_vault_address(network: str) -> str:
    return _cfg["vaults"][network]


def _headers() -> dict:
    return {"Authorization": f"Bearer {_cfg['api_key']}"}


def get_vault_info(network: str) -> dict:
    addr = get_vault_address(network)
    resp = requests.get(
        f"{_BASE_URL}/vault/{addr}",
        headers=_headers(),
        params={"network": network},
        timeout=15,
    )
    if resp.status_code != 200:
        raise ValueError(f"DeFindex /vault/{addr} returned {resp.status_code}: {resp.text}")
    return resp.json()


def get_vault_balance(network: str, public_key: str) -> dict:
    addr = get_vault_address(network)
    resp = requests.get(
        f"{_BASE_URL}/vault/{addr}/balance",
        headers=_headers(),
        params={"from": public_key, "network": network},
        timeout=15,
    )
    if resp.status_code != 200:
        raise ValueError(
            f"DeFindex /vault/{addr}/balance returned {resp.status_code}: {resp.text}"
        )
    return resp.json()


def build_deposit_xdr(network: str, public_key: str, amount_stroops: int) -> str:
    addr = get_vault_address(network)
    resp = requests.post(
        f"{_BASE_URL}/vault/{addr}/deposit",
        headers=_headers(),
        params={"network": network},
        json={"amounts": [amount_stroops], "caller": public_key},
        timeout=15,
    )
    if resp.status_code != 200:
        raise ValueError(
            f"DeFindex /vault/{addr}/deposit returned {resp.status_code}: {resp.text}"
        )
    return resp.json()["xdr"]


def build_withdraw_xdr(network: str, public_key: str, amount_stroops: int) -> str:
    addr = get_vault_address(network)
    resp = requests.post(
        f"{_BASE_URL}/vault/{addr}/withdraw",
        headers=_headers(),
        params={"network": network},
        json={"amounts": [amount_stroops], "caller": public_key},
        timeout=15,
    )
    if resp.status_code != 200:
        raise ValueError(
            f"DeFindex /vault/{addr}/withdraw returned {resp.status_code}: {resp.text}"
        )
    return resp.json()["xdr"]


def submit_transaction(signed_xdr: str, network: str) -> dict:
    """Fallback submission via DeFindex API (not used by default)."""
    resp = requests.post(
        f"{_BASE_URL}/send",
        headers=_headers(),
        params={"network": network},
        json={"xdr": signed_xdr, "launchtube": False},
        timeout=15,
    )
    if resp.status_code != 200:
        raise ValueError(
            f"DeFindex /send returned {resp.status_code}: {resp.text}"
        )
    return resp.json()


def decimal_to_stroops(amount_str: str) -> int:
    """Convert a decimal USDC string to stroops (integer, 7 decimal places)."""
    return round(float(amount_str) * 10_000_000)
