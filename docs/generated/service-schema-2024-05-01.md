# APIM service schema inventory (`2024-05-01`)

Source: Microsoft Azure REST API specification
[`apimdeployment.json`](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/apimanagement/resource-manager/Microsoft.ApiManagement/ApiManagement/stable/2024-05-01/apimdeployment.json).

The executable inventory is
`e2e/differential/testdata/service-2024-05-01.json`. The emulator retains the
complete request document, projects typed runtime fields into SQLite, and
overwrites server-owned fields when returning a service. This prevents new or
currently uninterpreted fields from disappearing during PUT, GET, list, or
PATCH operations.

## Resource envelope

`id`, `name`, `type`, `tags`, `location`, `sku`, `identity`, `systemData`,
`etag`, `zones`, and `properties`.

## Service properties

The stable schema contains the service-specific `publisherName` and
`publisherEmail` fields plus these inherited base properties:

`additionalLocations`, `apiVersionConstraint`, `certificates`,
`configurationApi`, `createdAtUtc`, `customProperties`,
`developerPortalStatus`, `developerPortalUrl`, `disableGateway`,
`enableClientCertificate`, `gatewayRegionalUrl`, `gatewayUrl`,
`hostnameConfigurations`, `legacyPortalStatus`, `managementApiUrl`,
`natGatewayState`, `notificationSenderEmail`, `outboundPublicIPAddresses`,
`platformVersion`, `portalUrl`, `privateEndpointConnections`,
`privateIPAddresses`, `provisioningState`, `publicIPAddresses`,
`publicIpAddressId`, `publicNetworkAccess`, `restore`, `scmUrl`,
`targetProvisioningState`, `virtualNetworkConfiguration`, and
`virtualNetworkType`.

## Evidence

`make test-differential` always validates the complete local field inventory.
With `APIM_AZURE_SERVICE_URL` and `APIM_AZURE_BEARER_TOKEN`, it also performs a
read-only Azure GET, rejects unclassified upstream fields, replays the document
locally, and compares every writable service field. It never modifies the
Azure service.
