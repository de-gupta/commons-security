# themis

`themis` is a lean Java 25 JWT verification library.

Its current job is deliberately narrow:

- verify a signed JWT
- normalize trusted claims into a stable token model
- return either a verification success or a verification failure with a reason

It is not a Spring Security auto-configuration library, and it does not handle login, token issuance, refresh, or
revocation/version checks.

## Dependency

```xml

<dependency>
    <groupId>io.github.de-gupta</groupId>
    <artifactId>themis</artifactId>
    <version>${latest-release-version}</version>
</dependency>
```

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

The main public API lives in:

- `de.gupta.commons.security.api`
- `de.gupta.commons.security.domain.model`

## Quick Start

Create a verifier:

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

Other supported verifier kinds:

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

1. create a `TokenVerifier` once for one trust domain
2. call `verify(...)` for each incoming token
3. on `VerificationSuccess`, use the returned `NormalizedToken`
4. on `VerificationFailure`, react based on `VerificationFailureReason`

One verifier instance should usually represent one issuer/key setup.

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

## What Themis Does Not Do

`themis` currently does not:

- issue tokens
- refresh tokens
- register or authenticate users
- resolve users from a database
- resolve roles from a database
- perform version/revocation checks
- auto-wire Spring Security filters or beans
- verify JWTs from JWK sets or key locators

Those concerns are intentionally outside the current scope of this module.

## Current Scope And Status

For the current goal, `themis` is in good shape as a small verification core for shared-secret and public-key JWTs.

It already gives you:

- a stable verifier API
- a policy model
- a normalized verified-token model
- explicit success/failure results
- no Spring dependency in the public usage model

## Known Gaps

The main feature gaps right now are:

- there is no dedicated Spring adapter module yet
- there is no key-locator or JWK-set support yet
- failure details are not yet populated beyond the enum reason
- documentation is still early and public Javadocs are still missing
- test coverage exists, but the new API surface could still use broader tests for issuer and audience combinations

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