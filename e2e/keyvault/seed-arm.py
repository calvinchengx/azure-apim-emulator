#!/usr/bin/env python3
"""Give the default stack a vault resource and one role assignment.

ARM governs this emulator by default, and ARM's rule is Azure's: no
assignment means no access. Without a seed, `docker compose up` would stand up
a vault that refuses its own quickstart -- more configuration to get started,
not less. So the stack seeds exactly what Azure gives you when you create a
vault in the portal: the resource, and a grant for the principal that created
it.

Everything here is reachable by hand; the file is the documentation for it.
Opt out with KV_ARM_URL= (see docker-compose.yml).

Stdlib only, like the family's other scripts.
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

ENTRA = os.environ["SEED_ENTRA_URL"]
ARM = os.environ["SEED_ARM_URL"]
TENANT = os.environ["SEED_TENANT_ID"]
SUB = os.environ["SEED_SUBSCRIPTION_ID"]
RG = os.environ["SEED_RESOURCE_GROUP"]
VAULT = os.environ["SEED_VAULT_NAME"]
CLIENT = os.environ["SEED_CLIENT_ID"]
SECRET = os.environ["SEED_CLIENT_SECRET"]

# Key Vault Secrets Officer: read and write secrets, which is what a
# quickstart does. A real Azure identifier, unchanged by the emulator.
ROLE = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
SCOPE = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.KeyVault/vaults/{VAULT}"
# Fixed, so re-running the seed is idempotent rather than piling up grants.
ASSIGNMENT = "6f9619ff-8b86-d011-b42d-00c04fc964ff"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # self-signed emulator certs


def http(method, url, token=None, body=None):
    req = urllib.request.Request(url, method=method,
                                 data=body.encode() if body else None)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)


def token(resource):
    body = (f"grant_type=client_credentials&client_id={CLIENT}"
            f"&client_secret={SECRET}&scope={resource}")
    req = urllib.request.Request(
        f"{ENTRA}/{TENANT}/oauth2/v2.0/token", data=body.encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, context=CTX, timeout=10) as r:
        return json.load(r)["access_token"]


def principal_of(jwt):
    import base64
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return claims.get("oid") or claims["sub"]


def main():
    # ARM's readiness is a compose healthcheck, but entra's token endpoint and
    # ARM's provider routes settle independently; retry rather than race.
    for attempt in range(30):
        status, _ = http("GET", f"{ARM}/health")
        if status == 200:
            break
        time.sleep(1)
    else:
        sys.exit("seed: arm-emulator never became reachable")

    arm_tok = token("https://management.azure.com/.default")
    kv_tok = token("https://vault.azure.net/.default")
    principal = principal_of(kv_tok)

    status, raw = http("PUT", f"{ARM}/subscriptions/{SUB}/resourcegroups/{RG}?api-version=2022-04-01",
                       arm_tok, '{"location":"westeurope"}')
    if status not in (200, 201):
        sys.exit(f"seed: resource group -> {status} {raw[:200]}")

    status, raw = http("PUT", f"{ARM}{SCOPE}?api-version=2024-11-01", arm_tok,
                       json.dumps({"location": "westeurope",
                                   "properties": {"tenantId": TENANT,
                                                  "accessPolicies": [],
                                                  "enableRbacAuthorization": True}}))
    if status not in (200, 201):
        sys.exit(f"seed: vault resource -> {status} {raw[:200]}")

    status, raw = http(
        "PUT",
        f"{ARM}{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{ASSIGNMENT}"
        f"?api-version=2022-04-01",
        arm_tok,
        json.dumps({"properties": {
            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/{ROLE}",
            "principalId": principal,
            "principalType": "ServicePrincipal"}}))
    # 409 means a previous `up` already seeded it, which is success here.
    if status not in (200, 201, 409):
        sys.exit(f"seed: role assignment -> {status} {raw[:200]}")

    print(f"seed: {VAULT} governed by ARM; Key Vault Secrets Officer -> {principal}")


if __name__ == "__main__":
    main()
