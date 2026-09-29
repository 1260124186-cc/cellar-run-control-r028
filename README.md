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

- `GET /healthz` (no authentication)

Caller and token administration:

- `POST /v1/callers` (unauthenticated only for the one-time first caller)
- `GET /v1/callers`
- `GET /v1/callers/me`
- `GET /v1/callers/{id}`
- `POST /v1/callers/{id}/revoke`

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

## Local Token Authentication

Every `/v1` business route requires a bearer token:

```text
Authorization: Bearer cellar_0123456789abcdef0123456789abcdef01234567
```

Enroll the first caller on an empty data directory (the bootstrap token is
returned exactly once and never stored in plain text):

```bash
curl -sS -X POST http://127.0.0.1:8088/v1/callers \
  -H 'Content-Type: application/json' \
  -d '{"name":"cellar-operator"}'
```

The response contains the caller record, the raw `token`, and
`expires_in_seconds`. Use the returned token for every later call, including
enrolling additional callers:

```bash
TOKEN='cellar_...'

curl -sS http://127.0.0.1:8088/v1/callers/me \
  -H "Authorization: Bearer $TOKEN"

curl -sS -X POST http://127.0.0.1:8088/v1/callers \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"production-script","ttl_seconds":86400}'

curl -sS -X POST http://127.0.0.1:8088/v1/callers/cli_xxxxxxxxxxxxxxxxxxxx/revoke \
  -H "Authorization: Bearer $TOKEN"
```

- `ttl_seconds` is optional (default 30 days; accepted range 1 second to 365
  days).
- Only the SHA-256 hash of each token is persisted in `state.json`.
- Revocation is idempotent and immediately visible to concurrent requests.
- `GET /healthz` remains unauthenticated.

Stable HTTP 401 error codes are `authentication_required`,
`malformed_authorization`, `token_unknown`, `token_expired`, and
`token_revoked`. Authenticated responses also carry an `X-Caller-ID` header.
If every token is lost, access is recovered by editing the data directory out
of band; there is intentionally no remote identity integration.

## Workflow Checks

Run each production workflow check separately:

```bash
go run ./cmd/fermentctl check formula-approval
go run ./cmd/fermentctl check vessel-run-lifecycle
go run ./cmd/fermentctl check observations-completion
go run ./cmd/fermentctl check local-token-auth
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
conflicting map indexes are not silently invented; invalid JSON, a negative
revision, or a corrupted caller record stops the process before HTTP serving
begins. Caller records and token-hash indexes are stored in the same snapshot,
so enrolled, expired, and revoked tokens survive restarts.

Authentication reads and revocations share the store's read/write lock: once a
revocation is committed and durable, no later request can authenticate with
that token.

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

The service does not control physical equipment, connect to a remote identity
provider, send notifications, expose a browser interface, or replicate data
across processes. Authentication is a self-contained local bearer-token
registry intended for a trusted local network or an internal adapter.
