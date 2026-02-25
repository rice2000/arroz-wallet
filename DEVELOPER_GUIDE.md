# Building a Stellar DeFi Wallet with Claude Code
## A Developer's Field Report: Stellar + DeFindex + Etherfuse on Testnet

**Project:** Arroz Wallet — a Python/Flask web wallet for Stellar with DeFi yield and MXN fiat on/off ramp
**Stack:** Python 3, Flask, stellar-sdk, Bootstrap 5
**Status:** Testnet complete. Mainnet pending.
**Repo:** https://github.com/rice2000/arroz-wallet

---

## What We Were Trying to Build

A complete MXN → yield → MXN loop using real DeFi infrastructure on Stellar:

```
MXN (bank) → CETES (Etherfuse on-ramp)
           → USDC (Stellar DEX swap)
           → DeFindex vault (yield)
           → USDC (withdraw)
           → CETES (Stellar DEX swap)
           → MXN (Etherfuse off-ramp)
```

The goal was a simple, self-hosted localhost wallet that a developer could use to test this entire flow — no custodians, no Node.js build step, secret key never leaves the machine.

The three external integrations were:
- **[Stellar](https://stellar.org)** — the base layer: keypairs, payments, trustlines, DEX
- **[DeFindex](https://defindex.io)** — Soroban-based yield vaults; deposits earn APY via Blend/Yieldblox strategies
- **[Etherfuse](https://etherfuse.com)** — Mexican treasury bill tokenization (CETES) + MXN ↔ CETES on/off ramp

---

## How We Built It

The project was built iteratively with Claude Code across two days, in clearly defined milestones. Each milestone was planned, implemented, tested, and committed before moving to the next.

### Phase 1: CLI Wallet (Milestone 1) — ~1 hour

**What was built:** A Python CLI wallet using the Stellar SDK. Keypair generation with Fernet-encrypted secret key storage (`PBKDF2HMAC` + `AES-128-CBC + HMAC-SHA256`, 480,000 iterations). Password entered via `getpass`, used only in memory to decrypt for signing. XLM balance via Horizon. Payment sending. Transaction history.

**No significant friction.** The stellar-sdk is well-documented and the basic wallet operations are straightforward. Fernet handles the encryption complexity cleanly.

**Key design decision:** The secret key is stored encrypted with a user-chosen password. The public key is stored plaintext. Nothing sensitive is ever written to disk unencrypted. `wallet.json` is gitignored.

---

### Phase 2: Web UI (Milestone 2) — ~1 hour

**What was built:** A Flask 3 web frontend wrapping all CLI features. Bootstrap 5 via CDN (no Node.js). Dashboard, create wallet, send, history, network switcher (testnet/mainnet stored in Flask session).

**Gotcha 1: macOS port 5000 conflict.** Flask defaults to port 5000. On macOS Monterey+, AirPlay Receiver also binds to port 5000 and silently intercepts requests — returning 403 instead of passing them to Flask. Switched to port 5001.

**Gotcha 2: Unfunded account exception leaked to UI.** When a wallet exists but has never been funded on Stellar (account not found on ledger), the Stellar SDK raises `NotFoundError`. This was caught by the generic `except Exception` handler and rendered as a raw JSON exception dump in the browser. Fixed by importing and catching `NotFoundError` separately, showing a clean "account not funded" message instead, and adding a Friendbot button.

---

### Phase 3: Stellar RPC Migration + Multi-Asset (Milestone 3) — ~1.5 hours

**What was built:** Migrated balance queries and transaction submission from Horizon to Stellar RPC (`SorobanServer`). Added non-XLM asset tracking with a user-managed list stored in `wallet.json`.

**Why Stellar RPC instead of Horizon?** Horizon is being deprecated as the primary API. More importantly, Soroban contract interactions require RPC. However, Horizon is still kept for transaction history — RPC has no account-filtered history endpoint.

**Gotcha: `LedgerEntryData` vs `LedgerEntry` XDR parsing.** This was the most technically subtle bug of the project. Stellar RPC's `getLedgerEntries` returns `LedgerEntryData` XDR in `entries[].xdr`, not the full `LedgerEntry` wrapper that includes a type discriminator. Parsing it as `LedgerEntry` shifted all byte offsets by the size of the wrapper, causing the account's ed25519 key bytes to be interpreted as a `PublicKeyType` enum — producing the error *"-1876849738 is not a valid PublicKeyType"*. The fix is to parse as `xdr.LedgerEntryData.from_xdr(entry.xdr)` directly.

**Key design constraint: No automatic trustline enumeration via RPC.** Horizon's `/accounts/{id}` returns all balances in a single call. Stellar RPC requires knowing the asset upfront to query a specific trustline ledger key — there is no "list all assets for this account" RPC method. This means the wallet maintains a `tracked_assets` list in `wallet.json` and the user must manually add assets they want to see. This is a fundamental architectural constraint, not a bug.

---

### Phase 4: DeFindex Yield Vault (Milestone 4) — ~2 hours

**What was built:** A self-contained `defindex.py` API client and `/vault` page. The flow: user submits an amount and password → app calls DeFindex API to get an unsigned XDR transaction → app decrypts the secret key locally and signs it → submits via Stellar RPC. The vault card on the dashboard shows live APY, user balance, and TVL. Gracefully disabled if `defindex.json` is absent.

**Gotcha 1: API path was `/vault/` (singular), not `/vaults/`.** The initial implementation used `/vaults/{addr}`. The live API returned `Cannot GET /vaults/...`. Correct path confirmed from the OpenAPI spec at `https://api.defindex.io/api-json`.

**Gotcha 2: Balance endpoint parameter was `from`, not `user`.** Sending `?user=<pubkey>` returned a 400. The OpenAPI spec shows the required parameter is `from`. Easy fix, but only discoverable by reading the spec or hitting the error.

**Gotcha 3: Deposit/withdraw request body schema was wrong.** Initial body: `{"user": pubkey, "amount": N}`. Actual schema: `{"amounts": [N], "caller": pubkey}`. The `amounts` field is an array (vaults are multi-asset), and the sender is `caller`, not `user`.

**Gotcha 4: Template field names were wrong.** The balance response returns `{"dfTokens": "0", "underlyingBalance": ["0"]}`. The vault info has no `tvl` field — TVL is `totalManagedFunds[0].total_amount`. Discovered only at runtime.

**Gotcha 5: Deposit and withdraw return HTTP 201, not 200.** The initial client raised a `ValueError` on any non-200 response. Both the deposit and withdraw endpoints return 201. This caused a confusing error where the full XDR response was shown in the flash message as an "error." Fixed by checking `status_code not in (200, 201)`.

**Gotcha 6: Vault balances displayed in stroops.** `underlyingBalance[0]`, `dfTokens`, and `totalManagedFunds[0].total_amount` are all raw stroops integers (e.g. `6700000` instead of `0.67`). There's no indication of this in the API response or documentation. Fixed by dividing by 10,000,000 in both `vault.html` and `index.html`.

**Human intervention required:** Obtaining a DeFindex API key and vault contract addresses from the DeFindex team. These go in `defindex.json` (gitignored). The testnet vault address used was `CBMVK2JK6NTOT2O4HNQAIQFJY232BHKGLIMXDVQVHIIZKDACXDFZDWHN`.

---

### Phase 5: Trustlines (Milestone 5) — ~30 minutes

**What was built:** On-chain trustline creation from the `/assets` page. Before this milestone, assets could only be added to the local tracking list — there was no way to submit a `ChangeTrust` operation from the wallet itself. Added a "Create Trustline" form that builds, signs, and submits a `ChangeTrust` transaction, then automatically adds the asset to the tracking list on success.

**No significant friction.** `TransactionBuilder.append_change_trust_op()` works exactly as documented.

---

### Phase 6: Etherfuse Fiat Ramp (Milestones 6–6f) — ~5 hours

This was the most complex phase, requiring the most human intervention and iterative debugging.

**What was built:** A self-contained `etherfuse.py` API client and `/ramp` page. On-ramp: user enters MXN amount → app gets a quote → creates an order → order status appears in the table. Off-ramp: user enters CETES amount + password → app gets a quote → creates an order → signs and submits a Stellar payment to the CETES issuer address. Gracefully disabled if `etherfuse.json` is absent.

#### Sandbox API corrections (Milestone 6c)

Several API assumptions from the planning phase were wrong and only discovered through live testing:

| Assumption | Reality |
|------------|---------|
| Testnet uses `api.etherfuse.com` | Testnet uses `api.sand.etherfuse.com` (separate sandbox host) |
| CETES issuer is the same on all networks | Different issuer on testnet: `GC3CW7EDYRTWQ635VDIGY6S4ZUF5L6TQ7AA4MWS7LEQDBLUSZXV7UPS4` |
| `quoteAssets` is a positional array `["onramp", "MXN", "CETES"]` | `quoteAssets` is an object: `{"type": "onramp", "sourceAsset": "MXN", "targetAsset": "CETES:<issuer>"}` |
| Exchange rates endpoint is `GET /ramp/exchange-rates` | Correct endpoint is `GET /ramp/assets?blockchain=stellar` |
| `list_orders` uses 1-indexed pages | 0-indexed: `pageNumber: 0` for the first page |
| `list_orders` response key is `"orders"` | Response key is `"items"` |

**Gotcha: Auth header has no "Bearer" prefix.** Etherfuse uses `Authorization: <api_key>` directly, not `Authorization: Bearer <api_key>`.

#### Onboarding setup (Milestones 6d–6e)

This was the most friction-heavy part of the entire project.

**The `customer_id` / `bank_account_id` consistency requirement** is the most important thing to understand about Etherfuse. Every quote and order call must use the exact same `customer_id` + `bank_account_id` pair that was used to generate the onboarding URL the user completed. If the IDs don't match, you get:
- `"Proxy account not found"` or
- `"Bank account not found"`

even after completing KYC.

**The correct setup flow:**
1. Generate a UUID for `bank_account_id` yourself and write it to `etherfuse.json` **before** generating the onboarding link
2. The app auto-generates `customer_id` on first run
3. Generate the onboarding link (this binds those two IDs together on Etherfuse's side)
4. Complete the full Plaid flow using the **Personal** tab with pre-filled sandbox bank data
5. Never change either ID after completing onboarding

**Human intervention required for Etherfuse:**
- Obtaining a sandbox API key from [devnet.etherfuse.com](https://devnet.etherfuse.com)
- Generating a UUID for `bank_account_id`
- Completing the Plaid onboarding flow in a browser (cannot be automated)
- Registering the wallet's Stellar public key on the Etherfuse dashboard (required for CETES minting to actually reach the wallet on testnet)

#### Off-ramp transaction discovery (Milestone 6f)

The off-ramp doesn't return a deposit address in the order response. The correct behavior is to send CETES directly to the **CETES issuer address** — this burns the tokens on Stellar, and Etherfuse matches the payment to the pending order by the sender's public key and the order ID in the transaction memo.

**Gotcha: Off-ramp order response is nested.** The response is `{"offramp": {"orderId": "..."}}`, not flat. Accessing `order["orderId"]` directly caused a `KeyError`. Fixed by unwrapping: `offramp_data = order.get("offramp", order)`.

#### Simulating bank payment on testnet (Milestone 7)

On testnet there is no real bank transfer — created orders sit at `"created"` status indefinitely. Etherfuse provides a sandbox-only endpoint to simulate the fiat deposit:

```
POST https://api.sand.etherfuse.com/ramp/order/fiat_received
{"orderId": "your-order-uuid"}
```

**Gotcha: Newly created orders don't appear in `list_orders` immediately.** There is an indexing delay on the Etherfuse side. The "Simulate bank payment" button was initially tied to the order list — if the order wasn't in the list yet, the button didn't appear, and there was no way to trigger the simulation. Fixed by storing the order ID in the Flask session immediately after creation and displaying the simulate button from session state, independent of the order list.

**Gotcha: Order field names.** The `list_orders` response uses `orderType` (not `direction` or `type`), `amountInFiat` (not `fiatAmount`), and `status: "created"` for new orders (not `"pending"`). Only discoverable by inspecting the raw response.

---

### Phase 7: CETES ↔ USDC Swap + Full Loop (Milestone 7) — ~3 hours

**What was built:** A `/swap` page using Stellar's `path_payment_strict_send` for CETES → USDC and USDC → CETES. Live rates from Horizon `strict_send_paths`. 1% slippage tolerance on `dest_min`. Multi-hop path support.

#### The USDC issuer mismatch problem

This was the most interesting infrastructure challenge of the project.

The testnet DEX has live CETES/USDC liquidity against **USDC:GBBD47** (the common testnet Circle USDC). But the DeFindex vault was deployed against a **different USDC issuer: GATALTG**. These two USDCs have no bridge between them on the testnet DEX — zero liquidity, zero order book activity.

This means if you swap CETES → USDC:GBBD47 and then try to deposit into the DeFindex vault (which holds USDC:GATALTG), you get `TokenErrors.MissingTrustline` — not because you're missing a trustline, but because the assets are fundamentally different tokens.

**Resolution:** The user manually seeded a testnet market for USDC:GATALTG. With that liquidity in place, Horizon's `strict_send_paths` found a two-hop path: CETES → USDC:GBBD47 → USDC:GATALTG.

**Gotcha: `path=[]` means direct DEX only.** The initial implementation passed `path=[]` to `path_payment_strict_send_op`, which restricts the trade to a single direct DEX order book. The two-hop route requires the intermediate asset to be specified in `path`. Fixed by refactoring `_get_swap_rate` into `_get_swap_record` (returns the full Horizon path record) + `_path_from_record` (converts the record's `path` array to `Asset` objects), then passing the result to the transaction.

```python
# Before — direct only, two-hop route fails silently
.append_path_payment_strict_send_op(..., path=[])

# After — uses whatever path Horizon found
hop_path = _path_from_record(record)
.append_path_payment_strict_send_op(..., path=hop_path)
```

---

## Full Loop — Verified Working on Testnet

| Step | Route | Notes |
|------|-------|-------|
| MXN → CETES | `/ramp` on-ramp + simulate | Etherfuse sandbox; simulate button required on testnet |
| CETES → USDC | `/swap` | Two-hop path via USDC:GBBD47 |
| Deposit USDC | `/vault` | DeFindex vault; requires USDC trustline for vault's issuer |
| Withdraw USDC | `/vault` | |
| USDC → CETES | `/swap` | Reverse path |
| CETES → MXN | `/ramp` off-ramp | Sends CETES to issuer address with order ID as memo |

---

## Total Human Intervention Required

| Task | Required? | Notes |
|------|-----------|-------|
| Obtain DeFindex API key | Yes | From DeFindex team |
| Obtain Etherfuse sandbox API key | Yes | From devnet.etherfuse.com |
| Generate `bank_account_id` UUID | Yes | One-time; `python3 -c "import uuid; print(uuid.uuid4())"` |
| Complete Plaid onboarding | Yes | Browser-based; cannot be automated |
| Register wallet on Etherfuse dashboard | Yes | Required for CETES minting on testnet |
| Seed USDC:GATALTG testnet market | Yes | Required to bridge DEX USDC to vault USDC |
| Create CETES + USDC trustlines | Yes | Via `/assets` in the wallet UI |
| Fund wallet with testnet XLM | No | Friendbot button in the wallet UI |

The KYC/onboarding step and the testnet market seeding are the two points where Claude Code cannot help — they require human action in external systems.

---

## Timing Summary

These are real-session estimates across two days of development:

| Phase | Milestone | Estimated Time |
|-------|-----------|---------------|
| CLI wallet | 1 | ~1 hour |
| Web UI | 2 | ~1 hour |
| Stellar RPC + multi-asset | 3 | ~1.5 hours |
| DeFindex vault | 4 | ~2 hours |
| Trustlines | 5 | ~30 minutes |
| Etherfuse ramp (code) | 6–6b | ~1 hour |
| Etherfuse API debugging | 6c | ~1 hour |
| Etherfuse onboarding debugging | 6d–6e | ~2 hours |
| Off-ramp + end-to-end ramp | 6f | ~1 hour |
| Swap + full loop | 7 | ~3 hours |
| **Total** | | **~14 hours** |

About 80% of the time was code-generation and iteration by Claude Code. The remaining 20% was human time in external systems: the Etherfuse dashboard, the Plaid sandbox, creating trustlines, and seeding the testnet market.

---

## Gotcha Reference

A consolidated list of everything that bit us, for anyone following this path:

### Stellar
- **Stellar RPC returns `LedgerEntryData` XDR, not `LedgerEntry`.** Parse with `xdr.LedgerEntryData.from_xdr()`, not `xdr.LedgerEntry.from_xdr()`.
- **Stellar RPC can't list all trustlines.** You must know the asset upfront. Plan for a user-managed tracked assets list.
- **`SorobanServer.send_transaction()` returns `PENDING` immediately**, unlike Horizon's `submit_transaction()` which waits for ledger inclusion.
- **Horizon is still required for transaction history.** Stellar RPC has no account-filtered history endpoint.
- **Port 5000 is taken on macOS** (AirPlay Receiver). Use 5001.
- **`path=[]` in `path_payment_strict_send_op` means direct DEX only.** For multi-hop routes, you must pass the intermediate assets.

### DeFindex
- **API path is `/vault/` (singular), not `/vaults/`.**
- **Balance endpoint uses `?from=`, not `?user=`.**
- **Deposit/withdraw body is `{"amounts": [N], "caller": pubkey}`, not `{"amount": N, "user": pubkey}`.** `amounts` is an array.
- **Deposit and withdraw return HTTP 201, not 200.** Accept both.
- **All balances (`underlyingBalance`, `dfTokens`, `totalManagedFunds[n].total_amount`) are in stroops.** Divide by 10,000,000 before displaying.
- **The vault's USDC issuer may differ from the testnet DEX's USDC issuer.** Check `GET /vault/{addr}` → `assets[n].name` to find the exact issuer the vault expects, and ensure there's DEX liquidity for that issuer.

### Etherfuse
- **Testnet API is `api.sand.etherfuse.com`, not `api.etherfuse.com`.**
- **CETES issuer is different on testnet vs mainnet.** Testnet: `GC3CW7EDYRTWQ635VDIGY6S4ZUF5L6TQ7AA4MWS7LEQDBLUSZXV7UPS4`.
- **Auth header is `Authorization: <key>`, no "Bearer" prefix.**
- **`quoteAssets` is an object, not an array.** Use `{"type": "onramp", "sourceAsset": "MXN", "targetAsset": "CETES:<issuer>"}`.
- **Exchange rates endpoint is `GET /ramp/assets?blockchain=stellar`**, not `/ramp/exchange-rates`.
- **`list_orders` pages are 0-indexed.** Page 0 = first page.
- **`list_orders` response key is `"items"`**, not `"orders"` or `"data"`.
- **Order fields are `orderType` (not `direction`), `amountInFiat` (not `fiatAmount`), status starts as `"created"` (not `"pending"`).**
- **`customer_id` and `bank_account_id` must match exactly between onboarding and all subsequent API calls.** Generate `bank_account_id` yourself before generating the onboarding link; never change it afterward.
- **Off-ramp deposit address is the CETES issuer itself.** Sending CETES to the issuer burns them. Include the order ID as the Stellar transaction memo.
- **Off-ramp order response is nested:** `{"offramp": {"orderId": "..."}}`. Unwrap before accessing fields.
- **Newly created on-ramp orders don't appear in `list_orders` immediately.** Store the order ID in session state and show the simulate button from session, not from the list.
- **On testnet, CETES won't arrive until the wallet is registered on the Etherfuse dashboard.** Order status can reach `completed` without tokens being minted if the wallet isn't registered.
- **Testnet sandbox trigger:** `POST /ramp/order/fiat_received` with `{"orderId": "..."}` simulates the bank transfer and completes the order.

---

## What's Next: Mainnet

The code is network-aware throughout. Switching to mainnet requires:

1. **Etherfuse mainnet credentials** — real API key from [etherfuse.com](https://etherfuse.com), full KYC, real Mexican bank account
2. **DeFindex mainnet vault address** — update `defindex.json` (the mainnet USDC vault `CCFWKCD52JN...` is already in the config)
3. **Real USDC on Stellar mainnet** — issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`
4. **DEX liquidity check** — verify the mainnet CETES ↔ USDC path exists (the Yieldblox CETES strategy on mainnet suggests it does)
5. **CETES vault on mainnet** — a DeFindex vault using the CETES Yieldblox strategy exists on mainnet; obtain that vault address and add it to `defindex.json`

The mainnet network passphrase, Horizon URL, and RPC URL are already in `wallet.py`'s `NETWORKS` dict. No code changes are required for the network switch — just credentials and vault addresses.

---

## Architecture Notes

**Secret key security model:** The secret key is decrypted in memory only at transaction-signing time, discarded immediately after. The password is submitted via HTML form, used server-side, and never stored. `wallet.json`, `defindex.json`, and `etherfuse.json` are all gitignored.

**Graceful degradation:** DeFindex and Etherfuse features are fully optional. If their config files are absent, the wallet works as a standard Stellar wallet with no vault or ramp UI. No crashes, no error pages — the nav links and dashboard cards simply don't appear.

**No webhooks:** The wallet uses polling (page refresh) rather than webhooks for order status. This is intentional for a self-hosted localhost tool — no public endpoint to receive callbacks.

**Horizon vs RPC split:** Transaction submission and balance queries use Stellar RPC. Transaction history uses Horizon (still the only option for account-filtered history). This is noted with a `TODO` comment for migration when Stellar Portfolio APIs are available.
