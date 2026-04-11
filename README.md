# themis

`themis` is a small Java 25 library for verifying signed JWTs and returning a trusted, normalized token view.

It is intentionally narrow:

- verify a signed JWT against a configured key
- apply selected policy checks after signature verification
- normalize trusted claims into a stable result model
- return success or failure without taking over the rest of your authentication flow

`themis` does not issue tokens, manage users, perform revocation checks, or wire framework-specific security stacks for
you.

## Philosophy

This library exists for one boundary: deciding whether an incoming token is cryptographically trusted and policy-valid.

That means `themis` focuses on:

- signature verification
- expiry and not-before handling
- optional issuer validation
- optional audience validation
- optional subject requirement
- claim normalization for downstream code

It deliberately leaves adjacent concerns to the surrounding application or to other modules:

- token issuance
- refresh flows
- user lookup
- revocation and version state
- authorization decisions

## What You Provide

To use `themis`, a consumer provides three things:

- a verification configuration
- a key or secret for the signing algorithm
- a token string to verify

The configuration defines the post-signature policy:

- allowed clock skew
- whether a subject is required
- which audiences must be present
- which issuer is expected
- which custom claim names should be used for roles and token version

For time handling, `themis` uses the verifier's `Clock`.

That means:

- in production, use a live clock such as `Clock.systemUTC()`
- in tests, inject a fixed clock when you want deterministic temporal behavior

The verifier consults that clock at verification time, not just once when the verifier is created.

## What You Get Back

Verification returns one of two outcomes:

- success with a normalized token
- failure with a structured failure reason

On success, the normalized token gives convenient access to trusted values such as:

- subject
- issuer
- audiences
- roles
- version
- issued-at / expires-at / not-before timestamps
- simple string properties

On failure, the result tells you why verification was rejected, for example because the token was:

- malformed
- unsupported
- expired
- not yet valid
- signed with the wrong key
- missing a required subject
- carrying the wrong issuer
- carrying the wrong audience

## Audience Semantics

Audience validation is policy-driven.

- if no expected audiences are configured, audience validation is skipped
- if expected audiences are configured, the token must contain all of them

This is a superset check, not exact equality.

Examples:

- token has no audience, policy expects none: pass
- token has no audience, policy expects `service-a`: fail
- token has audiences `a, b, c`, policy expects `a`: pass
- token has audiences `a, b, c`, policy expects `a, b`: pass
- token has audiences `a, b, c`, policy expects `a, d`: fail

## Typical Usage Shape

The intended usage pattern is simple:

1. create one verifier for one trust domain
2. reuse that verifier for incoming tokens from that issuer/key setup
3. react to success or failure in application code
4. on success, use the normalized token instead of working with raw JWT claims directly

One verifier instance should usually correspond to one issuer and one verification policy.

If your application accepts tokens from multiple trust domains, create multiple verifiers.

## What This Library Does Not Decide

Even after a token is successfully verified, your application may still need to answer questions like:

- is this token revoked?
- is the token version still current?
- does this subject still exist?
- is this user allowed to do this action?

Those are intentionally outside the scope of `themis`.

## Testing

Run the test suite with:

```bash
mvn test
```

If you want deterministic temporal verification in your own tests, construct the verifier with a fixed clock.