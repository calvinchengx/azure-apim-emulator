import os
import time

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
result = client.api.begin_create_or_update(
    os.environ["APIM_RESOURCE_GROUP"],
    os.environ["APIM_SERVICE_NAME"],
    "python-sdk-api",
    {
        "display_name": "Python SDK API",
        "path": "python-sdk",
        "service_url": "http://127.0.0.1:1",
        "protocols": ["https"],
        "subscription_required": False,
    },
).result()
if result.name != "python-sdk-api":
    raise RuntimeError(f"unexpected API name: {result.name}")
print("Python APIM SDK witness passed")
