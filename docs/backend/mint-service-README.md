# MintService — reference self-hosted activation endpoint

`tools/MintService` is a reference, self-hostable ASP.NET Core minimal API (net8.0)
that exposes the single HTTP endpoint the add-in's `HttpMintClient` (see
`AuthService/Services/Licensing`) calls for online activation:

```
POST /activate
{ "code": "...", "device": "..." }
```

This is the **one piece First Option operates and self-hosts**. It is the only
component that holds the ES256 private signing key — the key never ships to
clients, never lives in the add-in, and never lives in the marketplace. Only
this service can mint a valid token.

## Responses

- `200 OK` `{ "token": "<JWT>" }` — the code was valid, the subscription is
  active, and a token bound to `device` was minted.
- `400 Bad Request` `{ "error": "<reason>" }` — missing `code`/`device` in the
  request body, or the code failed validation (invalid, not found, inactive
  subscription, marketplace unreachable, or a malformed marketplace
  response). The service intentionally collapses all validation failures
  into a single generic message so it doesn't leak which codes exist.

The add-in reaches this endpoint via the `FIRSTOPTION_MINT_URL` environment
variable (or equivalent app setting) on the client side — `HttpMintClient` is
constructed with that base URL and posts to `{FIRSTOPTION_MINT_URL}/activate`.

## Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `FIRSTOPTION_PRIVATE_PEM_PATH` | Filesystem path to the ES256 (P-256) private key, PEM-encoded. Loaded once at startup. **Never ships to clients** — keep it on the host running this service only, with filesystem permissions restricted to the service account. |
| `FIRSTOPTION_KID` | Key id embedded in the minted JWT's header (e.g. `"k1"`). Defaults to `"k1"` if unset. Lets the add-in select the matching public key when multiple keys are in rotation. |
| `FIRSTOPTION_ADDON` | The addon GUID that minted tokens license. Embedded in every token as the `addon` claim. |
| `FIRSTOPTION_MARKETPLACE_URL` | Base URL of the marketplace's redemptions endpoint, e.g. `https://marketplace.firstoption-es.com/api/subscriptions/redemptions`. The service appends `?code=<code>` and issues a `GET`. |

No marketplace credentials are required or configured — the redemptions
endpoint is unauthenticated (a plain `GET` with the code as a query
parameter). If the marketplace endpoint later requires authentication, this
service is where that credential would be added; it must never be given to
the add-in.

## Code validation flow

For each `/activate` request:

1. Parse `{code, device}` from the JSON body; reject with 400 if either is
   missing or blank.
2. `GET {FIRSTOPTION_MARKETPLACE_URL}?code={code}` against the marketplace.
3. Require `success: true` in the response envelope.
4. Require `payload.subscription.status == "active"` (case-insensitive).
5. Read `payload.subscription.end_date` as the token's expiry (`exp`).
6. On any failure (network error, timeout, non-2xx, missing/malformed
   fields, inactive subscription) — return `400 { "error": "invalid or
   inactive code" }`.
7. On success, mint an ES256-signed JWT with claims `iss=firstoption`,
   `addon`, `tier=paid`, `iat` (now minus 5 minutes, to tolerate clock
   skew), `exp` (the subscription's `end_date`), `device` (bound to the
   caller-supplied device id), and a random `jti`.

## Open risk: `end_date` payload shape

`ValidateCodeAsync` assumes the marketplace's redemptions response has this
shape:

```json
{
  "success": true,
  "payload": {
    "subscription": {
      "status": "active",
      "end_date": "2026-12-31T00:00:00Z"
    }
  }
}
```

`end_date` is parsed with `JsonElement.GetDateTime()` and converted to a Unix
timestamp (UTC) to use directly as the token's `exp`. **This has not been
verified against a live marketplace response** — if the real payload nests
`subscription` differently, uses a different field name for the expiry, or
returns the date in a format `GetDateTime()` can't parse (e.g. a Unix
timestamp, a date-only string, or a different timezone convention), this
call throws and is caught by the surrounding `try/catch`, which just
returns `(false, 0)` — i.e. every code will look invalid. If codes that
should be valid are being rejected, this is the first place to check:
add logging around `ValidateCodeAsync` and inspect the raw marketplace
response, then adjust the property path / date parsing to match reality.

## Running

```bash
export FIRSTOPTION_PRIVATE_PEM_PATH=/secure/path/to/private-key.pem
export FIRSTOPTION_KID=k1
export FIRSTOPTION_ADDON=<addon-guid>
export FIRSTOPTION_MARKETPLACE_URL=https://marketplace.firstoption-es.com/api/subscriptions/redemptions
dotnet run --project tools/MintService
```

**HTTPS is required in production.** This is a minimal API with no built-in
TLS termination configuration beyond ASP.NET Core defaults — run it behind a
reverse proxy (or configure Kestrel with a certificate) so the private key's
signing operations and the codes submitted by clients are never sent over
plain HTTP. Do not expose this service without TLS.

## Testing

This is a reference service and has no automated tests of its own — the
add-in side of online activation (`HttpMintClient`) is covered by the
`FakeMintClient`-based tests in `AuthService.Tests`, which don't require this
service to be running. Exercising this service end-to-end requires the four
environment variables above plus network access to a real (or stubbed)
marketplace redemptions endpoint.
