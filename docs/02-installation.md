# 02 - Installation

Four ways to run it, in the order most people want them.

## Container

```bash
docker run --rm -p 8445:8445 \
  -e APIM_DISABLE_AUTH=true -e APIM_DISABLE_TLS=true \
  ghcr.io/calvinchengx/azure-apim-emulator:0.3.0
```

The image is distroless and runs as `nonroot`. Pin the version: `latest`
exists, but a pinned tag is what makes a CI run reproducible, and the family's
`docker-compose.yml` pins every member for the same reason.

State lives at `/data` inside the container. It persists only if you give it a
volume:

```bash
docker run --rm -p 8445:8445 -v apim-data:/data \
  -e APIM_DISABLE_AUTH=true -e APIM_DISABLE_TLS=true \
  ghcr.io/calvinchengx/azure-apim-emulator:0.3.0
```

To run a throwaway stack that leaves nothing behind, set `APIM_DATA_DIR` to the
empty string, which selects in-memory state. That is an explicit empty value,
not an unset one: unset means "use the default directory".

The image carries a `healthcheck` subcommand, which is what Compose should use
rather than curl, since the image has no shell tools:

```yaml
healthcheck:
  test: ["CMD", "/usr/local/bin/azure-apim-emulator", "healthcheck"]
  interval: 5s
  timeout: 3s
  retries: 10
```

**Images from 0.3.0 and earlier report their version as `dev`.** The Dockerfile
did not stamp it, so the image could not say which release it was while the
tarball from the same tag could. Fixed from 0.4.0 on, where the image and the
tarball report the identical string. On an older image, the tag is the only
source of truth for what you are running.

## Release binary

Every release publishes tarballs for macOS, Linux and Windows on amd64 and
arm64, plus `checksums.txt`:

```bash
VERSION=0.3.0
curl -sSLO https://github.com/calvinchengx/azure-apim-emulator/releases/download/v$VERSION/azure-apim-emulator_${VERSION}_linux_amd64.tar.gz
tar xzf azure-apim-emulator_${VERSION}_linux_amd64.tar.gz
./azure-apim-emulator version
```

```
azure-apim-emulator 0.3.0
```

## go install

```bash
go install github.com/calvinchengx/azure-apim-emulator/cmd/azure-apim-emulator@v0.3.0
```

This builds from source, so it reports its version as `dev` for the same reason
the container does: the version is injected at release time by the release
build, not recorded in the source.

## From a checkout

The loop the developers use, with authentication and TLS off:

```bash
git clone https://github.com/calvinchengx/azure-apim-emulator
cd azure-apim-emulator
APIM_DISABLE_AUTH=true go run ./cmd/azure-apim-emulator --disable-tls
```

`make verify` runs the full build, test, 100% coverage gate and vet suite.

## The pair, with real token validation

Everything above disables ARM authentication, which is fine for exploring and
wrong for testing anything that depends on identity. `compose.yaml` in the repo
runs this emulator against `entra-emulator`, which issues the tokens it
validates:

```bash
make up
```

That builds this emulator **from source** and pulls a pinned `entra-emulator`.
The pair listens on `https://localhost:8446` (host 8446, because
`arm-emulator` holds 8445 across the family compose) and validates every
management request against the issuer named in `APIM_ENTRA_ISSUER`.

To run the whole family together instead — Entra, ARM, Key Vault, Fabric,
Databricks and this — use
[azure-emulators](https://github.com/calvinchengx/azure-emulators), the
composition-only repo that holds the shared `docker-compose.yml` and pins every
member's version.

## Ports

| what | where | why |
|---|---|---|
| single process, dev | `8445` | the emulator's own default |
| this repo's `compose.yaml` | host `8446` → container `8445` | `arm-emulator` holds 8445 in the family compose |
| management requests | host `management.azure.localhost` | same split as Azure: one process, two hostnames |
| gateway requests | `{service}.azure-api.localhost`, or `localhost` for the seeded service | |

Running the dev binary on 8445 next to a containerised `arm-emulator` will
collide. Change one of them with `--addr`.

## Next

- [01-quickstart.md](01-quickstart.md) publishes an API and calls it.
- [04-configuration.md](04-configuration.md) documents every flag and variable.
