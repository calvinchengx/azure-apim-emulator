# Security

This is a **development tool**: an emulator of Azure API Management for local
testing. It is not Azure, holds no real credentials by design, and must never
front production traffic or store production secrets. TLS uses a locally
generated self-signed certificate; seeded identities are public knowledge.

## Reporting

Report vulnerabilities privately via
[GitHub security advisories](https://github.com/calvinchengx/azure-apim-emulator/security/advisories/new)
— not in public issues. Reports are read by the maintainer; expect an initial
response within a week.

## Supported versions

The latest release only.
