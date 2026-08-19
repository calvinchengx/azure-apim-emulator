# 04 - Configuration

Every setting, what it defaults to, and which ones change behaviour in ways
worth knowing about.

Each runtime setting is an `APIM_*` environment variable; most also have a
command flag, and **the flag wins** because it is parsed after the environment.
Settings with no flag are marked below.

## Listener and identity of the service

| variable | flag | default | what it does |
|---|---|---|---|
| `APIM_ADDR` | `--addr` | `:8445` | listen address |
| `APIM_DATA_DIR` | `--data-dir` | `./data` | state directory; **empty means in-memory** |
| `APIM_DEFAULT_SERVICE` | `--default-service` | `emulator` | the seeded service, and the one plain `localhost` gateway requests are routed to |
| `APIM_LOCATION` | `--location` | `local` | the seeded service's location |
| `APIM_DISABLE_TLS` | `--disable-tls` | off | serve plain HTTP instead of HTTPS |

**`APIM_DATA_DIR` distinguishes unset from set-empty**, and the difference is
whether anything survives a restart. Unset takes the default and persists to
`./data`; explicitly empty runs entirely in memory. The compose files use the
empty form deliberately, so a throwaway stack leaves no SQLite file in a
container layer that is about to be deleted. The family persists by default
because an emulator that forgets its services on restart is a surprise.

An empty value from the *environment* falls back to the default. Only the
*flag* can be empty enough to be rejected: `--addr ""` and
`--default-service ""` both fail to start.

## Authentication

| variable | flag | default | what it does |
|---|---|---|---|
| `APIM_DISABLE_AUTH` | `--disable-auth` | off | accept management requests with no bearer token |
| `APIM_ENTRA_ISSUER` | `--entra-issuer` | none | the trusted Entra v2 issuer |
| `APIM_ENTRA_JWKS_URL` | `--entra-jwks-url` | derived | where to fetch signing keys |
| `APIM_ENTRA_TLS_INSECURE` | `--entra-tls-insecure` | off | skip TLS verification when fetching JWKS |

**`APIM_ENTRA_ISSUER` is required unless authentication is disabled**, and the
process refuses to start without one:

```
APIM_ENTRA_ISSUER is required unless APIM_DISABLE_AUTH=true
```

It must parse as a URL with a scheme and a host, or startup fails naming the
value it rejected. When `APIM_ENTRA_JWKS_URL` is not set it is derived from the
issuer: a trailing `/` and `/v2.0` are stripped and `/discovery/v2.0/keys` is
appended.

`APIM_ENTRA_TLS_INSECURE` exists for the family compose, where `entra-emulator`
serves a self-signed certificate. It disables verification for JWKS fetches
only. Do not use it against anything you did not start yourself.

## Enforcement switches, both off by default

| variable | flag | default | what it does |
|---|---|---|---|
| `APIM_ENFORCE_RBAC` | *(none)* | off | make role assignments an access decision |
| `APIM_RBAC_OWNER` | *(none)* | none | the principal treated as Owner at subscription scope |
| `APIM_ENFORCE_TIERS` | *(none)* | off | refuse capabilities the service's SKU does not have |
| `APIM_STRICT_POLICIES` | `--strict-policies` | off | reject unsupported policies at upload instead of ignoring them |

**Off by default means the emulator is more permissive than a tenant, and that
is a real divergence rather than a neutral default.** With RBAC enforcement
off, any valid ARM token gets full access. With tier enforcement off, a
Developer-tier service will happily create workspaces, which Azure allows only
on Premium. Both defaults exist because every existing caller, test and witness
assumes them; turning them on is opting in to being refused. `parity.md` says
so in the rows concerned.

**`APIM_ENFORCE_RBAC` requires `APIM_RBAC_OWNER`** and refuses to start
without it:

```
APIM_RBAC_OWNER is required when APIM_ENFORCE_RBAC=true: with no owner, no role assignment can ever be created
```

That is not a nag. A role assignment is itself an ARM resource whose creation
needs a role, so with no owner nobody could ever grant the first one. Azure
resolves the same circularity with the subscription owner, whose access does
not come from an assignment either.

## How booleans are read

`1`, `true`, `yes` and `on` are true, in any case. **Everything else is
false**, including `2`, so a typo silently leaves the switch off rather than
failing. Checking startup logs is the way to confirm which mode you are in.

## Subcommands

| command | what it does |
|---|---|
| `azure-apim-emulator version` | prints the version |
| `azure-apim-emulator healthcheck` | probes `/health` on `APIM_ADDR`, HTTPS first then HTTP; the right Compose healthcheck for a distroless image with no shell tools |

`version` prints `dev` unless the binary came from a release tarball; see
[02-installation.md](02-installation.md).

## Test-harness variables

These affect the test suites, not the running emulator, and are listed so that
a search for `APIM_` finds them:

| variable | what it does |
|---|---|
| `APIM_RUN_EXTERNAL_SDK_TESTS` | run the four official-SDK witnesses |
| `APIM_RUN_OPERATION_INVENTORY` | probe all published `2024-05-01` operations (611 of them, one fresh service each) |
| `APIM_WRITE_INVENTORY` | rewrite the committed coverage report instead of asserting it |
| `APIM_SPEC_DIR` | regenerate the operation inventory from a local spec checkout instead of the network |
| `APIM_UPDATE_CORPUS`, `APIM_UPDATE_EVALUATION`, `APIM_UPDATE_LEDGER` | regenerate checked-in expression and policy fixtures |
| `APIM_ENDPOINT`, `APIM_GATEWAY_ENDPOINT`, `APIM_SUBSCRIPTION_ID`, `APIM_RESOURCE_GROUP`, `APIM_SERVICE_NAME`, `APIM_BACKEND_URL`, `APIM_PORT` | wiring the harnesses pass to SDK and protocol witnesses |
| `APIM_AZURE_SERVICE_URL`, `APIM_AZURE_BEARER_TOKEN` | point the differential harness at a real Azure service |

## Next

- [01-quickstart.md](01-quickstart.md) to see these in use.
- [09-identity-networking-observability.md](09-identity-networking-observability.md)
  for how token validation actually works.
