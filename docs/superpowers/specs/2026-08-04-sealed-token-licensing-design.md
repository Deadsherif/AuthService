# Sealed-Token Licensing — Design & Plan

**Date:** 2026-08-04
**Status:** Draft for review
**Scope:** Replace the client-side trust model in AuthService with offline-verifiable signed license tokens.

---

## Problem (one sentence)

Today the customer's machine makes the licensing decision (forgeable cache, mutable `public static Status`, attacker-controlled clock, secrets baked in the DLL), so any determined user bypasses it. We move the *decision* to a signer that holds a private key, and reduce the client to *verifying a signature* with an embedded public key.

## The contract (load-bearing — everything else depends on this)

A license token is a **JWT/JWS signed with ECDSA P-256 (`ES256`)**.

**Header**
- `alg`: `ES256`
- `typ`: `JWT`
- `kid`: key identifier (enables rotation — verifier can hold more than one public key)

**Claims (payload)**
- `iss` — issuer identifier (who minted it)
- `addon` — the add-in GUID this token licenses (matches the existing addin ID)
- `tier` — e.g. `trial` | `paid` (replaces the `IsTrial` flag)
- `iat` — issued-at (unix time)
- `exp` — expiry (unix time) = subscription end date
- `device` — hash of the device fingerprint this token is bound to
- `jti` — unique token id (reserved for future revocation; verifier ignores it for now)

**Why these choices:** `ES256` is native to `System.Security.Cryptography` on .NET Framework 4.7/4.8 **and** .NET 8, so the shipped add-in needs no third-party crypto dependency. JWT/JWS is standard, debuggable on jwt.io, and familiar to backend engineers — which matters for the hand-off in Part 3.

This contract is the single interface between the three parts below. If it is correct, the signer (ours now, backend later) and the verifier (the add-in) fit together with no code changes beyond swapping the public key.

---

## Part 1 — Work in AuthService (the client / add-in)

All of this is client-side and ships on our own schedule. No backend dependency.

**Verification core**
- Embed the **public key** as configuration, keyed by `kid`. Support holding **two** keys at once so rotation never bricks issued tokens.
- Add a JWT verification path (Microsoft.IdentityModel.Tokens works across net47/net48/net8): verify `ES256` signature → reject if invalid.
- Enforce claims: `addon` matches the calling add-in, `exp` in the future, `tier` recognized.

**Replace the forgeable cache**
- The stored artifact becomes the signed token itself — **not encrypted** (it is tamper-evident by signature, and it is not secret). Retire the AES key/IV and encrypt/decrypt code in `LocalAuthCache`.
- Store `maxDateSeen` alongside the token.

**Anti-rollback (time) — needs nothing from the marketplace**

The token gives two sealed, trustworthy time facts: `exp` (expiry) and `iat` (issued-at). `iat` is a hard **floor** — "now" can never legitimately be earlier than the moment the token was signed.

Construction:
- Seed `maxDateSeen = iat` at install.
- Each run: `maxDateSeen = max(maxDateSeen, iat, localClock, every successful online time reading)`. The ratchet only ever moves **forward**.
- Compare `maxDateSeen` (not the raw clock) against `exp` for the expiry decision.

Why untrusted time sources are safe to consume: because the ratchet takes the **max**, a lying source can't help an attacker — a fake *earlier* time is ignored (max keeps the higher value), and a fake *later* time only expires the attacker's own token sooner. So the marketplace does **not** need to serve a cryptographically trusted clock.

Reuse the existing `DateHelper` online fetches (marketplace redemption `time`, aisenseapi, ipgeolocation) as ratchet inputs — more independent sources is strictly better here. The **fix** is: never treat the `DateTime.Now` fallback as authoritative (today it is returned and trusted, which is the hole); the local clock may only push the ratchet forward, never justify a "now" below the floor.

Residual limit: an attacker who **freezes the clock and stays permanently offline** keeps the ratchet frozen and the token alive until `exp`. Internet closes this — any online moment re-anchors `maxDateSeen` to the real date. A signed time endpoint (Part 3 wishlist) would additionally defend against an attacker who MITMs their own outbound HTTPS; not needed for the realistic threat model.

Hygiene (same file): remove the hardcoded ipgeolocation API key (shipped secret — rotate it) and fix the `.GetAwaiter().GetResult()` sync-over-async.

**Device identity**
- Replace MAC-only (`GetCurrentMacAddress`) with binding to the **Windows MachineGuid** (a stable per-install id), matched **exactly** (`device` claim = hex SHA-256(MachineGuid)). A composite "fuzzy" fingerprint was rejected: fuzzy tolerance over a single joint SHA-256 hash is cryptographically impossible (preimage resistance), and binding to a stable identifier achieves the low-false-lockout goal directly — MachineGuid survives NIC swaps, docking, VPN, and disk changes, changing only on OS reinstall/sysprep (which costs one re-activation).

**Activation UX (Auth window)**
- **Online path:** customer pastes the short purchase code → add-in calls the mint endpoint → receives and stores the token.
- **Air-gapped path:** add-in displays the device fingerprint; customer mints the token elsewhere and pastes the long token in; add-in verifies and stores it.

**Remove the bypasses**
- Delete the instant-valid shortcut in `Auth.HasCacheEntry` / `ValidateAuth` (existence of a cache key currently returns Valid with no checks).
- Remove the public setter on `SubscriptionService.Status` (no mutable global trust flag).
- Remove hardcoded `admin`/`admin` (`FirstOptionPremiseAuth`) and the API key + admin scope from the shipped client. Treat all shipped secrets as already compromised — rotate regardless.

**Reliability fixes (surfaced during review)**
- Remove `.GetAwaiter().GetResult()` sync-over-async in `SubscriptionService` / `DateHelper` (UI-thread deadlock risk).
- Wrap `async void` handlers (`ExecuteSubmit`) so an exception can't crash the CAD host.
- Fix `IsMacValid` `break`→`continue` and the `GetTried = GetTried++` no-op.

**Compatibility**
- Keep `Auth.ValidateAuth(...)`'s public signature stable so consuming add-ins need no changes.

## Part 2 — Our signing / verification tooling (proves the client works; also the interim mint)

A small internal tool **we own**, used to (a) generate keys, (b) mint tokens for testing and — if we choose — for real activation until/unless the backend takes over, and (c) produce test vectors that prove the client behaves.

- **Key-generation script:** produce an ECDSA P-256 key pair. Private key → secured (never ships). Public key → exported (JWK/PEM) with a `kid`, for embedding in the client.
- **Minting script:** input claims (`addon`, `tier`, `exp`, `device`, …) → output a signed `ES256` JWT. This doubles as the interim production signer we run ourselves.
- **Test vectors** the client test suite must handle correctly:
  - valid token → accepted
  - tampered payload → rejected
  - expired `exp` → rejected
  - wrong `device` → rejected
  - signed by wrong key → rejected
  - clock rolled back below `maxDateSeen` → rejected
- **Rotation drill:** mint under key A, embed keys A+B in verifier, confirm both accepted; retire A, confirm A rejected.

This part means the entire product is testable and shippable **today**, with zero backend involvement.

## Part 3 — Task for the backend engineers (hand-off; no implementation details)

We hand them the **contract** above and this list of asks. *How* they build it is their call.

- Provide a **mint endpoint**: given a valid purchase/redemption code, return a signed license token; reject invalid/expired codes.
- Sign tokens with the **agreed cryptography and format** (we supply the exact contract: algorithm, token format, claim set).
- Set token **expiry to the subscription end date**.
- Hold the **private signing key** securely server-side; it must never leave the server or appear in any client.
- Provide us the corresponding **public key** and its **key id (`kid`)** for embedding in the add-in.
- Support **key rotation** (identify keys by `kid` so keys can change without breaking issued tokens).
- Apply endpoint **authentication, rate limiting, and abuse protection** as they see fit.
- (Optional, if we later want it) provide a **signed revocation list** at a fixed URL so tokens can be killed before expiry.

---

## Sequencing

1. **Part 1 + Part 2 together, now** — build the verifier and the tooling against our own test keys; ship a fully working, self-owned product. Not blocked on anyone.
2. **Part 3 submitted in parallel** — one well-specified request so their queue time runs in the background.
3. **Cutover** — when the backend endpoint and production public key exist, swap the public-key constant (one change) and point activation at their endpoint. The shipped verifier does not change.

## Non-goals / honest limits

- This makes the *token* unforgeable; it does not stop someone patching the compiled add-in to skip the check — true of any client-side scheme. Binary-level defenses (Authenticode on our own DLL, obfuscation) are separate and lower-ROI.
- Offline license enforcement on customer-owned hardware is an economic deterrent, not a guarantee. Goal: make cracking cost more than a license, and enable server-side revocation over time.
