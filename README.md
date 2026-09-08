# Common.Security

Shared security library for Aegis applications.

## Package

Package ID: `Common.Security`

Current version: `1.0.0`

The library owns authentication and directory concerns such as Active Directory/LDAPS credential validation, directory user lookup, username normalization and authentication result models. Consuming applications remain responsible for application-specific sessions, roles and authorization.

## Build

```bash
dotnet restore Common.Security.slnx
dotnet build Common.Security.slnx -c Release
dotnet test Common.Security.slnx -c Release
dotnet pack Common.Security.csproj -c Release
```

Packages are published to GitHub Packages by the `build-package` workflow after successful pushes to `main`.

Consumers should pin an explicit package version so each application can upgrade Common.Security independently.
