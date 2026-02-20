# Changelog

## Milestone 3 — Stellar RPC Migration + Multi-Asset Support (2026-02-20)

### What was built

Migrated from Horizon to Stellar RPC for balance queries and transaction submission, and added support for tracking and sending non-XLM assets.

**Stellar RPC migration**

- Balance queries now use `SorobanServer.get_ledger_entries()` instead of Horizon's `/accounts/{id}`. The response returns raw `LedgerEntryData` XDR, which is parsed to extract the balance in stroops and converted to a decimal string (`stroops / 10_000_000`).
- Transaction submission now uses `SorobanServer.send_transaction()`. Unlike Horizon's `submit_transaction()`, this returns immediately with a `PENDING` status and a hash rather than waiting for ledger inclusion.
- Horizon is kept for transaction history only — Stellar RPC has no account-filtered history endpoint. Marked with a `TODO: migrate when Portfolio APIs are available` comment.
- Added `rpc_url` to both network configs and a `soroban_server` global in `wallet.py`, initialized alongside the existing `server` (Horizon) on network selection.

**Multi-asset support**

Stellar RPC cannot enumerate all trustlines for an account (unlike Horizon's `/accounts/{id}` which returns every balance). The solution is user-managed asset tracking: assets to display are stored in `wallet.json` under `tracked_assets`, and each one is fetched individually via `getLedgerEntries` using the trustline ledger key.

- New `/assets` route and `assets.html` template — add an asset by code + issuer address, remove with a button
- `wallet.json` gains a `tracked_assets` field (empty array on wallet creation)
- Dashboard balance card replaced with a table showing XLM plus all tracked assets
- Send form gains an asset dropdown; value is `"native"` or `"CODE:ISSUER"`

**CLI updates**

- `check_balance()` uses the new RPC functions
- `send_payment()` supports asset selection and RPC submission
- Menu gains option 6: Manage tracked assets

### Issues discovered and fixed

**`LedgerEntryData` vs `LedgerEntry` XDR parsing**

The dashboard showed: *"-1876849738 is not a valid PublicKeyType"*

The Stellar RPC `getLedgerEntries` response returns `LedgerEntryData` XDR in `entries[].xdr` — not the full `LedgerEntry` wrapper. Parsing it as `LedgerEntry` shifted all byte offsets, causing the account's ed25519 key bytes to be interpreted as a `PublicKeyType` enum, producing an invalid value.

Fixed by using `xdr.LedgerEntryData.from_xdr(entry.xdr).account` (as the plan originally specified) rather than `xdr.LedgerEntry.from_xdr(entry.xdr).data.account`.

### Key design decision: why not auto-discover trustlines?

Horizon's `/accounts/{id}` returns all balances in one call. Stellar RPC's `getLedgerEntries` requires knowing each asset's ledger key upfront — there is no "list all trustlines for this account" RPC method. The user-managed `tracked_assets` list is the practical workaround until higher-level portfolio APIs exist.

---

## Milestone 2 — Web UI (2026-02-20)

### What was built

Added a Flask web frontend so the wallet can be used in a browser without touching the CLI. All existing wallet features are exposed:

- **Dashboard** (`/`) — shows public key (with copy button) and live XLM balance pulled from Horizon
- **Create Wallet** (`/create`) — generates a new keypair, encrypts it with a password, saves to `wallet.json`; on testnet, Friendbot is called automatically
- **Send XLM** (`/send`) — password is entered in the form, used server-side to decrypt the secret key and sign the transaction, then discarded
- **Transaction History** (`/history`) — fetches the 10 most recent transactions from Horizon
- **Network switcher** — navbar dropdown stores the chosen network in the Flask session and applies it on every request by setting the wallet.py globals (`server`, `NETWORK_PASSPHRASE`, etc.)

Stack: Flask 3, Jinja2 templates, Bootstrap 5 (CDN). No Node.js or build step.

### Issues discovered and fixed

**Port 5000 conflict (macOS AirPlay Receiver)**

Flask defaults to port 5000. On macOS Monterey and later, Control Center's AirPlay Receiver also binds to port 5000 — and intercepts connections before Flask can respond, returning a 403. Fixed by switching to port 5001.

**Unfunded account showing raw Horizon exception**

The wallet already had a `wallet.json` with a keypair that had never been funded on testnet. When the dashboard tried to fetch the balance, the Stellar SDK raised a `NotFoundError` (Horizon 404 — account not found on ledger), and the raw exception object was being rendered as a string in the UI, producing a wall of JSON.

Fixed in two steps:
1. Imported `stellar_sdk.exceptions.NotFoundError` and caught it separately from generic exceptions, so the dashboard could distinguish "account doesn't exist yet" from "something actually went wrong"
2. Added a `/fund` route and a **Fund with Friendbot** button on the dashboard that calls Friendbot on demand — so existing wallets can be activated without recreating them

After clicking the button, the account was funded with 10,000 testnet XLM and the balance displayed correctly.

### Server log (session)

```
13:21:10  GET  /           200   initial page load
13:21:24  POST /network    302   switched network (testnet → mainnet)
13:21:28  POST /network    302   switched back to testnet
13:21:31  GET  /history    200   viewed transaction history
13:21:51  GET  /create     200   viewed create wallet page
13:23:48  GET  /           200   returned to dashboard (saw raw 404 error)
            -- app.py patched: NotFoundError handling + /fund route --
13:25:56  GET  /           200   reloaded — now shows clean "not funded" message
13:26:03  POST /fund       302   Friendbot called — account funded (10,000 XLM)
13:26:03  GET  /           200   balance now shows 10,000.0000000 XLM
13:29:08  GET  /send       200   opened send page to test payment
```
