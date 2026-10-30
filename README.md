# Common.Security

Shared authentication and authorization library for the application family.

## Repository policy

`main` is the authoritative trunk and the only branch that should be used for ongoing development, integration, packaging, and releases. Older feature/integration branches are historical once their work has been incorporated into `main`.

## Package

Package ID: `Common.Security`

Candidate contract version: `2.0.0` (coordinated source migration required).

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

`Common.Security` provides shared security mechanisms. Hosts retain business permissions and application records.

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


## Version 2 identity and session model

`AuthenticationResult.Succeeded` requires an immutable `VerifiedIdentity`; provider-scoped subject keys are the only external linking authority. Email and usernames are profile information. The Active Directory plugin resolves domain and user object GUIDs over the existing LDAPS path and rejects disabled directory accounts. `Common.Security.Hosting` owns strict code/PKCE OpenID Connect registration, tenant allowlists, cookies, rate limiting and shared account administration.

`IAccountStore` owns account state, approved immutable bindings and session versions. `RelationalAccountStore` supplies one application-scoped SQLite/PostgreSQL implementation with atomic audit, unique identities, serializable first-login provisioning, optional transactional business-record projection, approved migration imports, and revocation tombstones. Public applicants can be provisioned Active; staff and operators start Pending Access. Applications still decide permissions and approvals. A correct password or validated provider token grants no role.

Local credentials use application-scoped PBKDF2, lockout and one-use expiring recovery proofs. Mock authentication requires explicit enablement, Development or Demo, confirmed data isolation and a server-controlled identity allowlist. There is no arbitrary-user or administrative-role fallback.

ASP.NET cookies validate live account state/version. Shared opaque sessions provide the same enforcement for non-browser hosts. Shared suite handoffs expire within 60 seconds, bind audience, provider identity and version, and consume their nonce once in durable storage. Registered-machine proofs preserve existing PBKDF2 records, enforce explicit scopes, and use host-owned credential stores for rotation and revocation. Secret retrieval remains outside this library.

## Migration and emergency maintenance

Back up and rehearse restoration of the host database before applying any migration. Import approved immutable provider mappings with original account IDs and aliases; never infer bindings from email. Imports are atomic and repeated imports preserve later disabling or revocation. Multiple public provider bindings can be imported together. The optional business-record projection shares the security transaction; do not perform external side effects in that callback.

`Common.Security.Tools` is an offline OS-authorized maintenance command, with no HTTP endpoint or login fallback. It defaults to validation without database writes. Supply the connection through protected `COMMON_SECURITY_CONNECTION`, an owner-only JSON account manifest and, for local maintenance, an owner-only password file. Never put a password or connection secret in command-line arguments.

```sh
dotnet run --project Common.Security.Tools -- import --provider sqlite --application example --manifest approved.json --actor migration-ticket --apply
```

For emergency local enrollment use `enroll-local` with one explicitly approved LocalDatabase account and `--password-file`; for an already enrolled local account use `recover-local`. Recovery changes the hash and session version atomically and cannot convert an external account. Application administrators must separately approve the account's application role and explicitly configure the intended local login source. Restore the normal source after testing recovery. Keep a second approved administrator and protected audit evidence. Never enable mock authentication for recovery.

The common tables are additive and contain no business/financial transformations. After new writes, preserve them and reconcile identity/audit changes forward; do not restore a stale database over current business records. Roll back the application binary independently, retain a protected snapshot and audit, and treat schema removal as a separately approved data operation. Rehearsing imports, recovery and restore against representative host data is a deployment gate.
