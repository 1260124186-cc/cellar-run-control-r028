# Cellar Run Control

Cellar Run Control is a local Go HTTP service for coordinating a small
production cellar. It keeps formula approval, vessel availability, active
fermentation runs, gravity observations, conditioning, completion metrics, and
vessel cleaning in one deterministic process.

This repository is a healthy initialization baseline. It has no intentional
defects and no automated test suite. Tests are intentionally deferred to a
later engineering task; the production workflow checks in this repository
remain available for immediate build and behavior verification.

## Requirements

- Go 1.23 or later
- A writable local data directory
- No database, network service, or third-party module

## Build And Run

Build every package:

```bash
go build ./...
```

Start the service:

```bash
go run ./cmd/fermentctl serve
```

The default address is `127.0.0.1:8088`. The default snapshot directory is
`./data`.

Environment variables:

- `CELLAR_CONTROL_ADDR`: HTTP listen address.
- `CELLAR_CONTROL_DATA_DIR`: directory containing `state.json`.
- `CELLAR_CONTROL_TOKEN_TTL`: default token lifetime as a Go duration (for
  example `12h` or `720h`); defaults to 24h, clamped at 30 days.

Example:

```bash
CELLAR_CONTROL_ADDR=127.0.0.1:9099 \
CELLAR_CONTROL_DATA_DIR=/tmp/cellar-control \
go run ./cmd/fermentctl serve
```

## Directory Structure

```text
cmd/fermentctl                 service and workflow-check executable
internal/clock                 time boundary
internal/config                environment configuration
internal/domain                entities, validation, transitions, metrics
internal/httpapi               HTTP routes, JSON decoding, errors
internal/service               use-case orchestration
internal/storage               revisioned snapshot persistence
internal/workflowcheck         real HTTP production checks
```

## Public API

Health:

- `GET /healthz`

Token administration (open local endpoints, like health):

- `POST /v1/tokens`
- `GET /v1/tokens`
- `POST /v1/tokens/verify`
- `POST /v1/tokens/{id}/revoke`

Formula workflow:

- `POST /v1/formulas`
- `GET /v1/formulas`
- `GET /v1/formulas/{id}`
- `PUT /v1/formulas/{id}/steps`
- `POST /v1/formulas/{id}/approve`
- `POST /v1/formulas/{id}/retire`

Vessel workflow:

- `POST /v1/vessels`
- `GET /v1/vessels`
- `GET /v1/vessels/{id}`
- `POST /v1/vessels/{id}/finish-cleaning`
- `POST /v1/vessels/{id}/retire`

Run workflow:

- `POST /v1/runs`
- `GET /v1/runs`
- `GET /v1/runs/{id}`
- `POST /v1/runs/{id}/reserve`
- `POST /v1/runs/{id}/start`
- `POST /v1/runs/{id}/observations`
- `POST /v1/runs/{id}/conditioning`
- `POST /v1/runs/{id}/complete`
- `POST /v1/runs/{id}/abort`

Writes accept an optional `X-Expected-Version` header. Errors use a stable
shape:

```json
{
  "error": {
    "code": "revision_conflict",
    "detail": "the aggregate version does not match X-Expected-Version",
    "field": ""
  }
}
```

## Caller Authentication

Every business route (formulas, vessels, runs) requires a bearer token:

```
Authorization: Bearer tok_0f8e60ba98f78b08fedb.2f9c...e64
```

Register a caller to receive a token once. The presented secret is shown
only in that response; the snapshot stores just its SHA-256 hash:

```bash
curl -X POST http://127.0.0.1:8088/v1/tokens \
  -H 'Content-Type: application/json' \
  -d '{"caller":"cellar-operator","ttl_seconds":86400}'
```

`ttl_seconds` is optional (1 to 2592000); when omitted the configured
default lifetime applies. Caller names are trimmed and matched case
insensitively; a caller can hold one active token, so re-registration
requires revocation first. Revocation keeps the record (so the precise
revoked error is returned) and releases the caller name. `GET /v1/tokens`
lists records without any secret material, and `POST /v1/tokens/verify`
checks the presented token and returns its caller.

Authentication failures are stable and return HTTP 401 with a
`WWW-Authenticate: Bearer` header:

| Code | When |
| --- | --- |
| `token_missing` | no `Authorization` header on a business route |
| `token_malformed` | wrong scheme, extra fields, or token outside the issued format |
| `token_invalid` | well-formed token whose identifier or secret does not match |
| `token_expired` | token passed its expiry time |
| `token_revoked` | token was revoked |

`token_not_found` is 404, while duplicate registration is 409
`token_caller_conflict` and revoking twice is 409 `invalid_token_state`.
The authenticated caller record is attached to the request context so any
business handler can identify who is calling.

Tokens are stored in the same revisioned snapshot as business state, so
they survive restarts. A request is authorized at the point its token
check reads the snapshot; revocation is serialized in the same store, so
requests authenticated before it commits proceed and every later request
is rejected as revoked. `GET /healthz` and the token administration routes
remain unauthenticated; they are intended, like the service itself, for a
trusted local network or internal adapter.

## Workflow Checks

Run each production workflow check separately:

```bash
go run ./cmd/fermentctl check formula-approval
go run ./cmd/fermentctl check vessel-run-lifecycle
go run ./cmd/fermentctl check observations-completion
go run ./cmd/fermentctl check token-lifecycle
```

Each check creates a temporary snapshot directory, starts the real HTTP
handler on a loopback listener, issues JSON requests, verifies success and
failure behavior, and removes its temporary data.

## Persistence And Recovery

The service stores a complete revisioned snapshot at
`<data-directory>/state.json`. A write creates a temporary file in the same
directory, commits the encoded bytes durably, closes the handle, and renames
the result over the previous snapshot. The in-memory snapshot is replaced only
after that operation succeeds.

On startup, an existing snapshot is decoded and normalized. Unknown or
conflicting map indexes are not silently invented; invalid JSON or a negative
revision stops the process before HTTP serving begins.

## Repair-Ready Boundaries

The baseline intentionally keeps several independent behavior surfaces visible
for later engineering evaluation:

- formula name normalization and duplicate detection;
- target gravity and process-step range validation;
- aggregate version conflict checks;
- atomic vessel reservation and release;
- run state transition guards;
- observation sequence and time ordering;
- gravity movement and range checks;
- metric calculation and rounding;
- durable snapshot replacement and startup normalization.

These are production mechanisms, not injected defects. A later task can add
automated tests or request a focused repair without changing the public API.

## Test Boundary

This stage does not create unit tests, integration tests, test fixtures, or an
E2E suite. The later test task owns systematic coverage of validation limits,
state transitions, concurrency, persistence failures, and numeric edge cases.

## Scope

The service does not control physical equipment, connect to a remote
identity provider, send notifications, expose a browser interface, or
replicate data across processes. Token administration endpoints rely on
local network trust; there are no roles beyond caller identity. It is
intended for a trusted local network or an internal adapter.
