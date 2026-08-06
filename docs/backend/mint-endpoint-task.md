# Build a License-Token Mint Endpoint — Backend Task

You are building **one HTTP endpoint**. A desktop application (already built, not shown to you)
will call it with a purchase code and a device id, and expects back a **signed license token**.
The app verifies that token **offline** with an embedded public key — it never calls back to
check it. When you are done, we paste your endpoint's URL into the app's configuration and it
must work with **no further changes on our side**.

You may build this in any language, framework, or hosting you like. What is **not** negotiable is
the exact request/response shape and the exact token format below — match them byte-for-byte or
the app will reject every token.

---

## Task 1 — Expose the endpoint (exact HTTP contract)

Expose a single route the app will POST to. We will configure the app with its full URL.

**Request** (what the app sends):
- Method: `POST`
- Header: `Content-Type: application/json`
- Body (exactly these two string fields):
  ```json
  { "code": "aWiS1Tbo2bm", "device": "feb7ccf2ff65e95c4660e61e5c307adce25a768057d23df1d496aec10bea19f6" }
  ```
  - `code` — the customer's purchase/redemption code.
  - `device` — a 64-character lowercase hex string (a SHA-256 hash). **Treat it as opaque.**

**Success response:**
- Status: `200`
- Header: `Content-Type: application/json`
- Body (exactly this field name):
  ```json
  { "token": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJ..." }
  ```
  - `token` — the compact signed JWT from Task 3.

**Rejection response** (invalid code, expired, not found, any problem):
- Status: any non-2xx (use `400`).
- Body: optional `{ "error": "human-readable reason" }`.

**Hard rules:**
- Return `200` **only** when the body contains a real signed `token`. The app treats a `200`
  with no `token` field as a failure — never do that.
- Any failure → non-2xx. The app treats every non-2xx as "activation failed."
- Must be served over **HTTPS** in production.

---

## Task 2 — Validate the code (your logic, your data)

Before minting, confirm the `code` is real and currently entitled — however you store codes
(database, existing marketplace API, etc.). This part is entirely yours; we prescribe nothing.

- Unknown / inactive / expired / already-consumed code → reject (Task 1 rejection response).
- Valid code → determine its **subscription end date**. You will put that into the token's `exp`.

---

## Task 3 — Mint the token (exact format)

Produce a **JWT/JWS in compact form, signed with ECDSA P-256 + SHA-256 (`ES256`)**. No other
algorithm is accepted.

**Header:**
```json
{ "alg": "ES256", "typ": "JWT", "kid": "k1" }
```

**Payload (claims):**
| claim | value |
|-------|-------|
| `iss` | `"firstoption"` |
| `addon` | the exact add-in GUID **we give you** (see Task 5), e.g. `"9F4E7C9b-9B06-4E9D-92BD-1FD0A3A2D7F8"` |
| `tier` | `"trial"` or `"paid"` |
| `iat` | issued-at, **JSON number**, unix seconds — set to **`now − 300`** (5 minutes in the past, see note) |
| `exp` | expiry, **JSON number**, unix seconds — the subscription end date from Task 2 |
| `device` | **copy the request's `device` string verbatim** (see the critical rule below) |
| `jti` | a unique id per token (e.g. a UUID) |

**CRITICAL — the `device` claim:** copy the `device` value from the request into the `device`
claim **unchanged, byte-for-byte**. Do **not** hash it, re-hash it, lowercase/uppercase it,
trim it, validate its format, or substitute anything of your own. It is a fingerprint of the
customer's machine that only the app can produce; if you alter it by even one character, the
token will not activate on that machine. The endpoint is a pass-through for this value.

**Note on `iat`:** set it slightly in the past (`now − 300`). The app treats `iat` as the
earliest possible "now"; if you stamp the signer's exact clock, a customer whose clock lags by a
few seconds looks like they rolled their clock back, and activation is refused.

---

## Task 4 — Signing key material (must pair with the app's embedded public key)

The app verifies signatures with a **public key embedded inside it**, selected by the header
`kid`. A token only verifies if **the private key you sign with is the mathematical pair of that
embedded public key** AND the header `kid` matches. Pick **one** of these:

- **Option A (we supply the key):** we give you a P-256 **private key** (PEM) and its `kid`
  (`k1`). You sign with it. Nothing changes in the app.
- **Option B (you generate the key):** you generate a P-256 key pair, keep the private key on the
  server, and give us the **public key** (PEM) plus the `kid` you used. We embed that public key
  in the app and ship an update.

Either way: the **private key never leaves your server** and never appears in any response or
client. We hold only the public half.

---

## Task 5 — Values we will hand you

Before you start, we will provide:
- The **add-in GUID** to put in the `addon` claim (a fixed string).
- The **`kid`** to put in the header (`k1` unless we say otherwise).
- Under Option A: the **private signing key** (PEM). Under Option B: you return the **public
  key** (PEM) + `kid` to us.

---

## Acceptance — how we confirm it works

We consider the task done when all of these hold:

1. **Wire test (the real one):** we set your endpoint URL in the app, enter a **real valid code**
   on a real machine, and the app activates successfully with no other change.
2. **Shape:** a valid code returns `200` `{ "token": "<jwt>" }`; an invalid code returns a non-2xx.
3. **Signature:** a token you mint verifies as `ES256` against our public key (we check on
   jwt.io with the embedded public key — it must say "Signature Verified").
4. **Claims:** `iat`/`exp` are **numeric** unix seconds; `exp` equals the subscription end date;
   `iss`/`addon`/`tier`/`jti` are present; `kid` in the header matches the signing key.
5. **Device pass-through:** the `device` claim in the returned token is **identical** to the
   `device` string we POSTed — same 64 characters, unchanged.

You choose auth, rate limiting, abuse protection, hosting, and language. We only require the
contract above.

---

## (Optional, later) Revocation

If we later need to kill tokens before their `exp`, we will ask you to publish a **signed list of
revoked `jti` values** at a fixed URL. Not required for the first version.
