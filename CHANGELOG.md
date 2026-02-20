# Changelog

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
