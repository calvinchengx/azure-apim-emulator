using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.ApiManagement;
using Azure.ResourceManager.ApiManagement.Models;
using Azure.Core.Pipeline;

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
var serviceId = ApiManagementServiceResource.CreateResourceIdentifier(subscriptionId, resourceGroup, serviceName);
var service = client.GetApiManagementServiceResource(serviceId);
var data = new ApiCreateOrUpdateContent
{
    DisplayName = "NET SDK API",
    Path = "dotnet-sdk",
    ServiceUri = new Uri("http://127.0.0.1:1"),
	IsSubscriptionRequired = false,
};
data.Protocols.Add(ApiOperationInvokableProtocol.Https);
var operation = await service.GetApis().CreateOrUpdateAsync(WaitUntil.Completed, "dotnet-sdk-api", data);
if (operation.Value.Data.Name != "dotnet-sdk-api")
{
    throw new InvalidOperationException($"unexpected API name: {operation.Value.Data.Name}");
}
Console.WriteLine(".NET APIM SDK witness passed");

sealed class StaticCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new("sdk-token", DateTimeOffset.UtcNow.AddHours(1));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}
