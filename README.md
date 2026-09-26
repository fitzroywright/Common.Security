# Common.Security

Shared authentication and authorization library for the application family.

## Repository policy

`main` is the authoritative trunk and the only branch that should be used for ongoing development, integration, packaging, and releases. Older feature/integration branches are historical once their work has been incorporated into `main`.

## Package

Package ID: `Common.Security`

Current version: `1.0.0`

## Responsibilities

`Common.Security` provides provider-neutral authentication contracts, authorization, security telemetry, diagnostics integration, and plugin loading used across applications.

The library owns shared security capabilities including:

- Authentication provider contracts and dynamic authentication-plugin loading.
- Provider-neutral directory profile contracts and username normalization.
- Authentication result models and authentication abstractions.
- Application-role and permission authorization through `IPermissionAuthorizer` / `PermissionAuthorizer`.
- Direct user-to-role assignments.
- Directory-group-to-application-role mappings.
- Time-bound role assignments.
- Authorization decision auditing.
- Authorization administration services and abstractions.
- Dependency-injection registration for provider-neutral security and authorization services.
- Integration with `Common.Diagnostics` for security health checks and security-event reporting.

Consuming applications remain responsible for application-specific security policy and persistence. Each application defines the roles and permissions that make sense for its own domain and provides the storage implementation for role assignments, group mappings, time-bound assignments, audit records and related authorization data.

In short: `Common.Security` provides the reusable security mechanism; consuming applications provide their domain-specific policy and data.

## Current maturity

The reusable authentication/authorization framework is considered functionally implemented. Provider-specific authentication lives in separate plugins. The Active Directory/LDAPS provider is implemented by `Common.Security.Plugin.ActiveDirectory`; Common.Security core does not reference LDAP or Active Directory runtime libraries.

## Build

```bash
dotnet restore Common.Security.slnx
dotnet build Common.Security.slnx -c Release
dotnet test Common.Security.slnx -c Release
dotnet pack Common.Security.csproj -c Release
```

Packages are published to GitHub Packages by the `build-package` workflow after successful pushes to `main`.

Consumers should pin an explicit package version so each application can upgrade Common.Security independently.


## Authentication plugins

Applications load an implementation of `IAuthenticationPlugin` through `AuthenticationPluginLoader`. Provider-specific configuration belongs under `AuthenticationPlugin:Settings`.

The Active Directory implementation is in:

```text
Common.Security.Plugin.ActiveDirectory
```

The core `Common.Security` assembly intentionally contains no Active Directory authenticator, Active Directory options type, LDAP directory lookup implementation, or `System.DirectoryServices.Protocols` dependency.
