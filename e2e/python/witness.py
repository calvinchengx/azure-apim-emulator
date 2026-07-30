import os
import time

import requests
from azure.core.credentials import AccessToken
from azure.mgmt.apimanagement import ApiManagementClient


class StaticCredential:
    def get_token(self, *scopes, **kwargs):
        return AccessToken("sdk-token", int(time.time()) + 3600)


client = ApiManagementClient(
    StaticCredential(),
    os.environ["APIM_SUBSCRIPTION_ID"],
    base_url=os.environ["APIM_ENDPOINT"],
)
resource_group = os.environ["APIM_RESOURCE_GROUP"]
service_name = os.environ["APIM_SERVICE_NAME"]
client.api_management_service.begin_create_or_update(
    resource_group,
    service_name,
    {
        "location": "local",
        "sku": {"name": "Developer", "capacity": 1},
        "publisher_name": "Python SDK",
        "publisher_email": "python@example.test",
    },
).result()
result = client.api.begin_create_or_update(
    resource_group,
    service_name,
    "python-sdk-api",
    {
        "display_name": "Python SDK API",
        "path": "python-sdk",
        "service_url": os.environ["APIM_BACKEND_URL"],
        "protocols": ["https"],
        "subscription_required": True,
    },
).result()
if result.name != "python-sdk-api":
    raise RuntimeError(f"unexpected API name: {result.name}")
client.api_operation.create_or_update(
    resource_group,
    service_name,
    "python-sdk-api",
    "get",
    {"display_name": "Get", "method": "GET", "url_template": "/items"},
)
scope = (
    f"/subscriptions/{os.environ['APIM_SUBSCRIPTION_ID']}/resourceGroups/{resource_group}"
    f"/providers/Microsoft.ApiManagement/service/{service_name}/apis/python-sdk-api"
)
client.subscription.create_or_update(
    resource_group,
    service_name,
    "python-sdk-subscription",
    {
        "display_name": "Python SDK subscription",
        "scope": scope,
        "state": "active",
        "primary_key": "python-sdk-key",
        "secondary_key": "python-sdk-secondary",
    },
)
original_secrets = client.subscription.list_secrets(
    resource_group, service_name, "python-sdk-subscription"
)
if original_secrets.primary_key != "python-sdk-key" or original_secrets.secondary_key != "python-sdk-secondary":
    raise RuntimeError("Python SDK subscription secrets did not round-trip")
client.subscription.regenerate_primary_key(
    resource_group, service_name, "python-sdk-subscription"
)
rotated_secrets = client.subscription.list_secrets(
    resource_group, service_name, "python-sdk-subscription"
)
if rotated_secrets.primary_key == "python-sdk-key" or rotated_secrets.secondary_key != "python-sdk-secondary":
    raise RuntimeError("Python SDK subscription key did not rotate")
gateway_response = requests.get(
    f"{os.environ['APIM_ENDPOINT']}/python-sdk/items",
    headers={"Ocp-Apim-Subscription-Key": rotated_secrets.primary_key},
    verify=os.environ["REQUESTS_CA_BUNDLE"],
)
if gateway_response.status_code != 200 or gateway_response.text != "sdk-backend":
    raise RuntimeError(f"gateway response: {gateway_response.status_code}")
print("Python APIM SDK witness passed")
