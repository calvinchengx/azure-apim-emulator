# 01 - Quickstart

Publish an API and call it through the gateway, in about a minute, with nothing
running but this emulator.

Everything below is plain HTTP with authentication off, which is the fastest
loop for exploring. Two things need more than that and are covered at the end:
the **official Azure SDKs refuse to send a bearer token over HTTP**, and real
token validation needs `entra-emulator`.

## 1. Start it

```bash
docker run --rm -p 8445:8445 \
  -e APIM_DISABLE_AUTH=true -e APIM_DISABLE_TLS=true \
  ghcr.io/calvinchengx/azure-apim-emulator:0.3.0
```

Or from a checkout, which is the loop the developers use:

```bash
APIM_DISABLE_AUTH=true go run ./cmd/azure-apim-emulator --disable-tls
```

Either way it answers on `http://localhost:8445` and seeds one service:

```bash
curl -s http://localhost:8445/health
```

```json
{"now":1787142770,"service":"emulator","status":"ok"}
```

The seeded service is called `emulator`, in resource group `emulator-rg` under
subscription `00000000-0000-0000-0000-000000000000`. That full ARM path is used
often enough below to be worth a shell variable:

```bash
MGMT="http://localhost:8445"
SVC="/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/emulator-rg/providers/Microsoft.ApiManagement/service/emulator"
API="?api-version=2024-05-01"
```

**Management requests are addressed to a different host than gateway
requests**, exactly as in Azure, and this one process serves both. Management
goes to `management.azure.localhost`; gateway traffic goes to the service's own
hostname, or to plain `localhost` for the seeded service. With curl that is a
`Host` header.

## 2. Create an API and an operation

```bash
curl -s -X PUT -H "Host: management.azure.localhost" \
  -H "Content-Type: application/json" "$MGMT$SVC/apis/echo$API" \
  -d '{"properties":{"displayName":"Echo","path":"echo","protocols":["http","https"],"serviceUrl":"https://backend.invalid","subscriptionRequired":false}}'
```

```bash
curl -s -X PUT -H "Host: management.azure.localhost" \
  -H "Content-Type: application/json" "$MGMT$SVC/apis/echo/operations/get-message$API" \
  -d '{"properties":{"displayName":"Get message","method":"GET","urlTemplate":"/message"}}'
```

Both answer `201`.

`serviceUrl` points at `backend.invalid` on purpose: the next step answers from
a policy, so this API never calls a backend and the quickstart needs no second
service to be running.

## 3. Answer it from a policy

```bash
curl -s -X PUT -H "Host: management.azure.localhost" \
  -H "Content-Type: application/json" \
  "$MGMT$SVC/apis/echo/operations/get-message/policies/policy$API" \
  -d '{"properties":{"format":"xml","value":"<policies><inbound><base /><return-response><set-status code=\"200\" reason=\"OK\" /><set-header name=\"Content-Type\" exists-action=\"override\"><value>application/json</value></set-header><set-body>{\"message\":\"hello from the emulator\"}</set-body></return-response></inbound><backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>"}}'
```

## 4. Call it

```bash
curl -s http://localhost:8445/echo/message
```

```json
{"message":"hello from the emulator"}
```

That is the whole loop: the API, the operation and the policy are real ARM
resources, and the gateway compiled and served them.

## 5. Require a subscription key

APIM's usual posture is that callers present a key. Turn it on for this API:

```bash
curl -s -X PATCH -H "Host: management.azure.localhost" -H "If-Match: *" \
  -H "Content-Type: application/json" "$MGMT$SVC/apis/echo$API" \
  -d '{"properties":{"subscriptionRequired":true}}'
```

The same call now fails, with the error Azure returns:

```bash
curl -s http://localhost:8445/echo/message
```

```json
{"error":{"code":"SubscriptionKeyInvalid","message":"Access denied due to missing subscription key. Make sure to include subscription key when making requests to an API."},"statusCode":401}
```

Create a subscription scoped to the API, then read its key. **The key is not in
the PUT response** — Azure never returns subscription secrets from a create or
a get, and neither does this, so it comes from `listSecrets`:

```bash
curl -s -X PUT -H "Host: management.azure.localhost" \
  -H "Content-Type: application/json" "$MGMT$SVC/subscriptions/echo-sub$API" \
  -d '{"properties":{"displayName":"Echo subscription","scope":"'"$SVC"'/apis/echo"}}'

KEY=$(curl -s -X POST -H "Host: management.azure.localhost" \
  "$MGMT$SVC/subscriptions/echo-sub/listSecrets$API" | jq -r .primaryKey)
```

Both header and query forms work, as in Azure:

```bash
curl -s -H "Ocp-Apim-Subscription-Key: $KEY" http://localhost:8445/echo/message
curl -s "http://localhost:8445/echo/message?subscription-key=$KEY"
```

## 6. Use an official Azure SDK

**The Azure SDKs refuse to attach a bearer token to a non-HTTPS URL**, so the
`--disable-tls` mode above cannot be driven by them. Run with TLS instead,
which is the default:

```bash
APIM_DISABLE_AUTH=true go run ./cmd/azure-apim-emulator --data-dir ./data
```

On first start it writes a self-signed certificate to `./data/tls/cert.pem`
covering `management.azure.localhost`, `*.azure-api.localhost` and `localhost`.
It is its own issuer, so trust that file directly:

```python
import time
from azure.core.credentials import AccessToken
from azure.mgmt.apimanagement import ApiManagementClient

class Static:                      # auth is off, so any token will do
    def get_token(self, *s, **k):
        return AccessToken("t", int(time.time()) + 3600)

client = ApiManagementClient(
    Static(), "00000000-0000-0000-0000-000000000000",
    base_url="https://management.azure.localhost:8445",
)
api = client.api.begin_create_or_update("emulator-rg", "emulator", "sdk-api", {
    "display_name": "SDK API", "path": "sdk", "protocols": ["http"],
    "service_url": "https://backend.invalid", "subscription_required": False,
}).result()
print(api.name, api.path)
```

```bash
SSL_CERT_FILE=./data/tls/cert.pem REQUESTS_CA_BUNDLE=./data/tls/cert.pem python sdk.py
```

Unlike the curl steps, this one needs `management.azure.localhost` to actually
resolve, because the SDK builds the URL itself and there is no `Host` header to
override. macOS and most systemd hosts resolve every `*.localhost` name to
loopback already. If yours does not, pin it:

```
# /etc/hosts
127.0.0.1  management.azure.localhost
```

The Go, JavaScript, Python and .NET management SDKs are all exercised against
this emulator in CI; see [10-testing-and-sdk-matrix.md](10-testing-and-sdk-matrix.md)
for what each one covers.

## Next

- [02-installation.md](02-installation.md) to run it as a container, a binary,
  or the `entra-emulator` pair with real token validation.
- [04-configuration.md](04-configuration.md) for every flag and variable,
  including the two enforcement switches that are off by default.
- [parity.md](parity.md) for what is emulated and what is not. Nothing here is
  verified against Azure itself; the ledger says exactly what each claim rests
  on.
