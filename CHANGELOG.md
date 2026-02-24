# Changelog

## Milestone 5 — Trustline Creation (2026-02-24)

### What was built

Added on-chain trustline creation to the Assets page. Before this, `/assets` only managed a local tracking list — it had no ability to authorize the account to hold a non-XLM asset on the Stellar ledger. Users had to create trustlines out-of-band and then manually add the asset to the tracking list separately.

**`app.py`**

New `trustline` action in the `assets()` route. Decrypts the secret key with the wallet password, builds a `ChangeTrust` transaction via `TransactionBuilder.append_change_trust_op()`, signs and submits it via `SorobanServer`, then calls `add_tracked_asset()` on success so the asset appears on the dashboard immediately. `InvalidToken` is caught and re-renders the form with "Incorrect password."

**`templates/assets.html`**

Replaced the single "Add Asset" card with two clearly separated cards:

- **Create Trustline** — code, issuer, and password fields; submits the on-chain `ChangeTrust` transaction and adds to the tracking list in one step. Includes a mainnet warning banner.
- **Add to Tracking List** — the original form, kept for assets where a trustline already exists but isn't being tracked yet.

### Verified

Created a fresh testnet wallet via Friendbot, then used the Create Trustline form with USDC (`GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5`). Transaction succeeded, USDC appeared in the dashboard balance table with a `0.0000000` balance, confirming the trustline is live on-chain.

---

## Milestone 4 — DeFindex Yield Vault Integration (2026-02-24)

### What was built

Added a yield vault feature powered by the DeFindex REST API. Users can see live APY and their vault balance on the dashboard, and deposit or withdraw USDC from a dedicated `/vault` page. The wallet fetches an unsigned XDR from DeFindex, signs it locally with the decrypted secret key, and submits it via the existing `SorobanServer` — the same pattern used by `/send`.

**New files**

- `defindex.py` — self-contained API client. Loads `defindex.json` at import time and sets `_CONFIGURED = False` if the file is missing, so the rest of the app degrades gracefully: the vault card is hidden on the dashboard and `/vault` redirects with a warning rather than crashing.
- `templates/vault.html` — stats card (APY, balance, dfTokens), deposit form, withdraw form, vault contract address footer. Mainnet warning banner mirrors `send.html`.
- `defindex.json` — API key + testnet/mainnet vault addresses. Added to `.gitignore`; never committed.

**`app.py` changes**

- Added `TransactionEnvelope` to the `stellar_sdk` import.
- `_sign_and_submit_xdr(unsigned_xdr, password, public_key)` — shared helper that decrypts the secret key, signs the DeFindex-provided XDR envelope, and submits via RPC.
- `index()` — fetches `vault_info` and `vault_balance` after the existing balance block; passes them to the template along with `vault_configured`.
- `vault()` — GET renders the vault page; POST validates action/amount/password, converts the decimal amount to stroops, calls `build_deposit_xdr` or `build_withdraw_xdr`, signs and submits, flashes the transaction hash on success or an error message on failure. Wrong password is caught as `InvalidToken` and re-renders the form with the amount preserved.

**Template changes**

- `base.html` — Vault nav link added after Assets.
- `index.html` — Vault stats card (APY, Your Balance, TVL) with Deposit/Withdraw buttons appears below the quick-actions row when `vault_configured` is true.

### Issues discovered and fixed during testing

**Wrong API path (`/vaults/` vs `/vault/`)**

The initial implementation used `/vaults/{addr}` (plural). The live API returned 404 with `"Cannot GET /vaults/..."`. The correct path is `/vault/{addr}` (singular), confirmed from the OpenAPI spec at `https://api.defindex.io/api-json`.

**Wrong balance query parameter (`user` vs `from`)**

The balance endpoint was called with `?user=<pubkey>`. The OpenAPI spec shows the required parameter is named `from`. Fixed in `get_vault_balance()`.

**Wrong deposit/withdraw request body**

Initial body was `{"user": pubkey, "amount": N}`. The `DepositDto` and `WithdrawDto` schemas require `{"amounts": [N], "caller": pubkey}` — amounts is an array (the vault is multi-asset) and the sender field is `caller`, not `user`.

**Wrong template field names**

The balance response returns `{"dfTokens": "0", "underlyingBalance": ["0"]}`, not `underlyingValue`. The vault info response has no top-level `tvl` field — TVL is `totalManagedFunds[0].total_amount`. Both templates updated accordingly.

**`submit_transaction()` endpoint**

The fallback submit helper was pointing to `/transactions/send`. The correct endpoint is `POST /send?network=` with body `{"xdr": ..., "launchtube": false}`.

---

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
