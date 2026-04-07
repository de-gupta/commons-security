# themis

`themis` is a lean Java 25 JWT verification library.

It does one job:

- verify a signed JWT
- validate selected claims against a policy
- normalize trusted claims into a stable token model
- return either a verification success or a verification failure

It does not try to be an auth server, a user-management system, or a Spring Security starter.

## Philosophy

`themis` is intentionally narrow.

The idea behind the library is simple:

- cryptographic trust is one concern
- token issuance is another concern
- stateful revocation/version checks are another concern
- application authorization is yet another concern

Those concerns are related, but they are not the same thing. `themis` focuses only on the cryptographic verification
boundary and on producing a clean, trusted token abstraction for downstream code.

That narrow scope is deliberate. It keeps the library:

- small
- predictable
- framework-agnostic
- easy to compose into larger security flows

## The Bigger Picture

`themis` is designed to work well on its own, but it also fits into a larger ecosystem.

A useful mental model is:

- `Hermes`: token issuance or token exchange
- `Themis`: token verification and normalization
- `Augustus`: token version or revocation-state checking
- `Argus`: orchestrator module: composition of the whole pipeline

In other words:

- `Hermes` says: "this identity should receive this token"
- `Themis` says: "this token is cryptographically trusted"
- `Augustus` says: "this trusted token is still current, according to system state"

## Architecture

At the public surface, `themis` exposes only two kinds of packages:

- `de.gupta.commons.security.api`
- `de.gupta.commons.security.domain.model`

Internally, the flow is layered:

1. verifier implementation
2. controller
3. facade
4. request adapter
5. service

That means the public API stays small, but the internal design still has clean seams for growth.

At runtime, the flow looks like this:

1. consumer creates a `TokenVerifier`
2. consumer calls `verify(token)`
3. `themis` adapts the raw token into a `VerificationRequest`
4. the service verifies signature and temporal constraints
5. the service validates configured policy checks
6. `themis` returns either:
    - `VerificationSuccess`
    - `VerificationFailure`

## What Themis Does

Today, `themis` supports:

- HMAC-signed JWT verification
- RSA-signed JWT verification
- EC-signed JWT verification
- expiry validation
- not-before validation
- optional subject requirement
- optional issuer validation
- optional audience validation
- normalized access to trusted claims after verification

## What Themis Does Not Do

`themis` currently does not:

- issue tokens
- refresh tokens
- register or authenticate users
- resolve users from a database
- resolve roles from a database
- perform version or revocation checks
- auto-wire Spring Security filters or beans
- verify JWTs from JWK sets or key locators

Those concerns are intentionally outside the scope of this module.

## Dependency

```xml

<dependency>
    <groupId>io.github.de-gupta</groupId>
    <artifactId>themis</artifactId>
    <version>${latest-release-version}</version>
</dependency>
```

## Public API

The main public entrypoints are:

- `TokenVerifierFactory`
- `TokenVerifier`
- `TokenVerificationPolicy`
- `VerificationResult`
- `VerificationSuccess`
- `VerificationFailure`
- `NormalizedToken`

## Consumer Overview

There are two main ways to consume `themis`.

### 1. Standalone verification

This is the simplest usage:

- create a verifier for one trust domain
- call `verify(...)`
- consume the result

### 2. Verification as one stage in a larger auth pipeline

This is the intended shape when you have multiple auth components:

- external token enters the system
- `Hermes` may exchange it into an internal token
- `Themis` verifies the token cryptographically
- `Augustus` checks token version or revocation state
- the application authorizes based on trusted claims and local policy

## Quick Start

Create an HMAC verifier:

```java
import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.api.TokenVerifier;
import de.gupta.commons.security.api.TokenVerifierFactory;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

final TokenVerifier verifier = TokenVerifierFactory.hmac(
		TokenVerificationPolicy.of(
				Duration.ofSeconds(30),
				true,
				Set.of("my-service"),
				Optional.of("https://issuer.example")
		),
		"0123456789abcdef0123456789abcdef"
);
```

Create RSA or EC verifiers:

```java
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

final TokenVerifier rsaVerifier = TokenVerifierFactory.rsa(policy, rsaPublicKey);
final TokenVerifier ecVerifier = TokenVerifierFactory.ec(policy, ecPublicKey);
```

Verify a token:

```java
import de.gupta.commons.security.domain.model.NormalizedToken;
import de.gupta.commons.security.domain.model.VerificationFailure;
import de.gupta.commons.security.domain.model.VerificationResult;
import de.gupta.commons.security.domain.model.VerificationSuccess;

final VerificationResult result = verifier.verify(jwtToken);

if(result instanceof
VerificationSuccess success)
		{
final NormalizedToken token = success.token();
final String subject = token.subject();
final Set<String> roles = token.stringListClaim("user_roles");
}
		else if(result instanceof
VerificationFailure failure)
		{
final var reason = failure.reason();
}
```

## Typical Consumer Flow

For the current scope, a consumer typically does this:

1. create a `TokenVerifier` once for one issuer/key setup
2. call `verify(...)` for each incoming token
3. on `VerificationSuccess`, use the returned `NormalizedToken`
4. on `VerificationFailure`, react based on `VerificationFailureReason`

One verifier instance should usually represent one trust domain.

That means a system can create multiple verifiers when it needs to verify tokens from different creators, for example:

- one verifier for external Supabase tokens
- another verifier for internal Hermes-issued tokens

## Verification Policy

`TokenVerificationPolicy` controls the non-cryptographic checks applied after signature verification.

Current policy options:

- `clockSkew`
- `requireSubject`
- `expectedAudiences`
- `expectedIssuer`

Convenience factories:

```java
TokenVerificationPolicy.create();
TokenVerificationPolicy.

of(Duration.ZERO);
TokenVerificationPolicy.

of(Duration.ZERO, true);
TokenVerificationPolicy.

of(Duration.ZERO, true,Set.of("audience"));
		TokenVerificationPolicy.

of(Duration.ZERO, true,Set.of("audience"),Optional.

of("issuer"));
```

### Audience behavior

Audience checking is policy-driven:

- if `expectedAudiences` is empty, no audience validation is performed
- if `expectedAudiences` is non-empty, the token audiences must contain all expected audiences

This means the check is a superset check, not exact equality.

Examples:

- token has no `aud`, policy expects none: pass
- token has no `aud`, policy expects `service-a`: fail
- token has `aud = ["a", "b", "c"]`, policy expects `["a"]`: pass
- token has `aud = ["a", "b", "c"]`, policy expects `["a", "b"]`: pass
- token has `aud = ["a", "b", "c"]`, policy expects `["a", "d"]`: fail

## Verification Results

`VerificationResult` is a sealed hierarchy:

- `VerificationSuccess`
- `VerificationFailure`

`VerificationFailure` currently returns one of these reasons:

- `MALFORMED`
- `INVALID_SIGNATURE`
- `EXPIRED`
- `NOT_YET_VALID`
- `MISSING_SUBJECT`
- `INVALID_ISSUER`
- `INVALID_AUDIENCE`
- `UNSUPPORTED`

## Normalized Token

On success, `themis` returns a `NormalizedToken`.

It currently exposes:

- `rawToken()`
- `subject()`
- `issuer()`
- `audiences()`
- `issuedAt()`
- `expiresAt()`
- `stringClaim(name)`
- `stringListClaim(name)`
- `longClaim(name)`

This lets consumers work with a trusted, normalized token model instead of depending directly on JJWT claim APIs.

## Test Coverage

Run tests normally with:

```bash
mvn test
```

Generate coverage reports with:

```bash
mvn clean verify -Pcoverage
```

JaCoCo reports are generated at:

- `target/site/jacoco/index.html`
- `target/site/jacoco/jacoco.xml`

At the current stage, local coverage is already strong enough for a v1 release:

- line coverage: 100%
- instruction coverage: above 98%
- branch coverage: above 90%