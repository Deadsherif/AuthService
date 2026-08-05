# License Token Mint Endpoint — Hand-off for Backend

The add-in verifies license tokens **offline**, using an embedded public key. This document
hands you the token **contract** the client already implements, plus the **asks** for a
server-side mint endpoint that produces tokens matching that contract. How you build the
endpoint is entirely your call — no implementation details are prescribed here.

## Token contract

A license token is a **JWT/JWS signed with ECDSA P-256 (`ES256`)**.

**Header**
- `alg`: `ES256`
- `typ`: `JWT`
- `kid`: key identifier (enables rotation — the client can hold more than one public key at once)

**Claims (payload)**
- `iss` — issuer identifier (who minted it)
- `addon` — the add-in GUID this token licenses
- `tier` — `trial` | `paid`
- `iat` — issued-at (unix time, seconds)
- `exp` — expiry (unix time, seconds) = subscription end date
- `device` — hex SHA-256 hash of the device fingerprint this token is bound to
- `jti` — unique token id (reserved for future revocation)

The client verifies the signature offline against an embedded public key (keyed by `kid`) and
checks these claims itself; it never calls back to any server to validate a token.

## Asks

- Provide a **mint endpoint**: given a valid purchase/redemption code, return a signed license
  token; reject invalid or expired codes.
- Sign tokens with the **agreed cryptography and format** above (ECDSA P-256 / ES256 JWT with
  the exact claim set) — no substitutions.
- Set token **`exp` to the subscription end date**.
- Hold the **private signing key** securely server-side. It must never leave the server or
  appear in any client.
- Give us the corresponding **public key** and its **key id (`kid`)** so we can embed it in the
  add-in.
- Support **key rotation**: identify keys by `kid` so keys can change without invalidating
  already-issued tokens.
- Apply endpoint **authentication, rate limiting, and abuse protection** as you see fit.
- Set `iat` to slightly **before** the actual signing time — e.g. `iat = now - 5 minutes` — so
  that a customer device whose clock lags the signer at the moment of activation is not falsely
  flagged as a clock rollback. The client treats `iat` as a hard lower bound on "now"; a token
  minted with `iat` equal to the signer's exact clock can appear to be from the future on a
  slightly slow client clock.
- (Optional, for later) provide a **signed revocation list** at a fixed URL so tokens can be
  killed before `exp`.
