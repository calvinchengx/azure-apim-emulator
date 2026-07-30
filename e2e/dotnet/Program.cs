using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.ApiManagement;
using Azure.ResourceManager.ApiManagement.Models;
using Azure.Core.Pipeline;
using Azure.ResourceManager.Resources;

var endpoint = new Uri(Environment.GetEnvironmentVariable("APIM_ENDPOINT")!);
var subscriptionId = Environment.GetEnvironmentVariable("APIM_SUBSCRIPTION_ID")!;
var resourceGroup = Environment.GetEnvironmentVariable("APIM_RESOURCE_GROUP")!;
var serviceName = Environment.GetEnvironmentVariable("APIM_SERVICE_NAME")!;

var options = new ArmClientOptions
{
	Environment = new ArmEnvironment(endpoint, "https://management.azure.com"),
	Transport = new HttpClientTransport(new HttpClient(new HttpClientHandler
	{
		ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
	})),
};
var client = new ArmClient(new StaticCredential(), subscriptionId, options);
var resourceGroupResource = client.GetResourceGroupResource(
    ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroup));
var serviceData = new ApiManagementServiceData(
    new AzureLocation("local"),
    new ApiManagementServiceSkuProperties(ApiManagementServiceSkuType.Developer, 1),
    "dotnet@example.test",
    "NET SDK");
await resourceGroupResource.GetApiManagementServices().CreateOrUpdateAsync(
    WaitUntil.Completed, serviceName, serviceData);
var serviceId = ApiManagementServiceResource.CreateResourceIdentifier(subscriptionId, resourceGroup, serviceName);
var service = client.GetApiManagementServiceResource(serviceId);
var data = new ApiCreateOrUpdateContent
{
    DisplayName = "NET SDK API",
    Path = "dotnet-sdk",
    ServiceUri = new Uri(Environment.GetEnvironmentVariable("APIM_BACKEND_URL")!),
    IsSubscriptionRequired = true,
};
data.Protocols.Add(ApiOperationInvokableProtocol.Https);
var operation = await service.GetApis().CreateOrUpdateAsync(WaitUntil.Completed, "dotnet-sdk-api", data);
if (operation.Value.Data.Name != "dotnet-sdk-api")
{
    throw new InvalidOperationException($"unexpected API name: {operation.Value.Data.Name}");
}
var operationData = new ApiOperationData
{
    DisplayName = "Get",
    Method = "GET",
    UriTemplate = "/items",
};
await operation.Value.GetApiOperations().CreateOrUpdateAsync(WaitUntil.Completed, "get", operationData);
var subscriptionData = new ApiManagementSubscriptionCreateOrUpdateContent
{
    DisplayName = "NET SDK subscription",
    Scope = operation.Value.Id.ToString(),
    State = SubscriptionState.Active,
    PrimaryKey = "dotnet-sdk-key",
    SecondaryKey = "dotnet-sdk-secondary",
};
await service.GetApiManagementSubscriptions().CreateOrUpdateAsync(
    WaitUntil.Completed, "dotnet-sdk-subscription", subscriptionData);
using var gatewayClient = new HttpClient(new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});
gatewayClient.DefaultRequestHeaders.Add("Ocp-Apim-Subscription-Key", "dotnet-sdk-key");
var gatewayResponse = await gatewayClient.GetAsync(new Uri(endpoint, "/dotnet-sdk/items"));
var gatewayBody = await gatewayResponse.Content.ReadAsStringAsync();
if (gatewayResponse.StatusCode != System.Net.HttpStatusCode.OK || gatewayBody != "sdk-backend")
{
    throw new InvalidOperationException($"gateway response: {gatewayResponse.StatusCode} {gatewayBody}");
}
Console.WriteLine(".NET APIM SDK witness passed");

sealed class StaticCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new("sdk-token", DateTimeOffset.UtcNow.AddHours(1));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}
