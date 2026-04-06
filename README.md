# commons-security

`themis` is a lean Spring Security helper library for JWT-based applications.

It keeps integration explicit: consumer applications import the library configuration themselves and decide where the
provided JWT filter is used in their own `SecurityFilterChain` definitions.

## Dependency

```xml

<dependency>
    <groupId>io.github.de-gupta</groupId>
    <artifactId>themis</artifactId>
    <version>${latest-release-version}</version>
</dependency>
```

## What The Consumer Must Do

To use this library in a service, the consumer must:

1. add the Maven dependency
2. import `SecurityLibraryConfiguration`
3. configure `security.jwt.secret`
4. define one or more `SecurityFilterChain` beans that use the provided `JwtFilter`
5. send bearer tokens whose subject is in `sub` and whose roles are in the configured roles claim

This library does not auto-register security for the application on its own. The consumer still owns the service's
Spring Security configuration and path rules.

## What The Consumer Gets

After importing the library configuration, the consumer gets these beans:

- `JwtParser`
- `JwtService`
- `JwtFilter`
- `SecurityContextQueryManager`

What those beans do:

- `JwtParser` verifies signed JWTs using the configured shared secret.
- `JwtService` verifies tokens and maps them into the library's typed `JwtPrincipal`.
- `JwtFilter` reads `Authorization: Bearer ...`, verifies the token, and populates the `SecurityContext` when valid.
- `SecurityContextQueryManager` is a small convenience API for reading the authenticated username and authorities from
  the current security context.

## Import The Library

```java
import de.gupta.commons.security.SecurityLibraryConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(SecurityLibraryConfiguration.class)
class SecurityImportConfiguration
{
}
```

## Required Configuration

```properties
security.jwt.secret=0123456789abcdef0123456789abcdef
```

The JWT secret is required and must contain at least 32 characters.

## Optional Configuration

```properties
security.jwt.roles-claim=realm_roles
```

Defaults:

- JWT subject comes from the standard `sub` claim.
- Authorities are read from `security.jwt.roles-claim`.
- The default roles claim is `user_roles`.

## Typical Consumer Configuration

```java
import de.gupta.commons.security.SecurityLibraryConfiguration;
import de.gupta.commons.security.api.chain.FilterChainFactory;
import de.gupta.commons.security.token.jwt.filter.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Import(SecurityLibraryConfiguration.class)
class ApplicationSecurityConfiguration
{
	@Bean
	@Order(1)
	SecurityFilterChain publicPaths(HttpSecurity http) throws Exception
	{
		return FilterChainFactory.exposePaths(http, new String[]{"/public/**"});
	}

	@Bean
	@Order(2)
	SecurityFilterChain adminPaths(HttpSecurity http, JwtFilter jwtFilter) throws Exception
	{
		return FilterChainFactory.securePathsWithAuthorities(
				http,
				new String[]{"/admin/**"},
				new String[]{"ROLE_ADMIN"},
				jwtFilter
		);
	}

	@Bean
	@Order(3)
	SecurityFilterChain applicationPaths(HttpSecurity http, JwtFilter jwtFilter) throws Exception
	{
		return FilterChainFactory.secureWithFilter(http, jwtFilter);
	}
}
```

## What Request Flow Looks Like

Once the consumer has imported the library configuration and wired `JwtFilter` into their security chains, the request
flow is:

1. a request reaches a path protected by a filter chain that includes `JwtFilter`
2. `JwtFilter` looks for the `Authorization` header
3. if the header starts with `Bearer `, the token is passed to `JwtService`
4. `JwtService` verifies signature, expiry, and presence of the JWT subject
5. if verification succeeds, the token is mapped to a `JwtPrincipal`
6. the authenticated principal is stored in Spring Security's `SecurityContext`
7. downstream authorization rules such as `hasAnyAuthority(...)` now see the user's roles
8. controllers and services can read the authenticated user from Spring Security or through
   `SecurityContextQueryManager`

If the token is missing, malformed, expired, or signed with the wrong secret, the request continues unauthenticated and
the service's own security rules decide the response.

## What The Service Can Read After Authentication

After successful JWT authentication:

- `Authentication#getName()` resolves to the JWT subject
- `Authentication#getPrincipal()` is a `JwtPrincipal`
- `JwtPrincipal#subject()` returns the JWT subject
- `JwtPrincipal#authorities()` returns the normalized roles extracted from the configured roles claim
- `SecurityContextQueryManager#username()` returns the current username
- `SecurityContextQueryManager#hasRole(...)` checks authorities case-insensitively

## JWT Rules Applied By The Library

- A token is accepted only when the signature is valid, the token is not expired, and the JWT subject is present.
- Missing or malformed tokens do not populate the `SecurityContext`.
- Missing roles claims are treated as an empty authority set.
- Invalid, expired, or malformed JWTs fail closed and leave the request unauthenticated.

## Minimal Adoption Checklist

- Add the dependency.
- Add `@Import(SecurityLibraryConfiguration.class)`.
- Set `security.jwt.secret`.
- Add a `SecurityFilterChain` that uses the injected `JwtFilter`.
- Choose which paths are public and which require authorities.
- Issue JWTs whose `sub` and roles claim match the library configuration.

## Test Coverage

Run:

```bash
mvn clean verify -Pcoverage
```

JaCoCo reports are generated at `target/site/jacoco/index.html` and `target/site/jacoco/jacoco.xml`.