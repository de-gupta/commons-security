package de.gupta.security.themis.domain.model;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

public sealed interface NormalizedToken permits DefaultNormalizedToken
{
	String rawToken();

	String subject();

	Set<String> roles();

	Optional<String> issuer();

	Set<String> audiences();

	Optional<Instant> issuedAt();

	Optional<Instant> expiresAt();

	Optional<Instant> notBefore();

	@Deprecated(since = "2.1.0", forRemoval = true)
	Optional<String> stringClaim(String name);

	@Deprecated(since = "2.1.0", forRemoval = true)
	Set<String> stringListClaim(String name);

	@Deprecated(since = "2.1.0", forRemoval = true)
	Optional<Long> longClaim(String name);
}