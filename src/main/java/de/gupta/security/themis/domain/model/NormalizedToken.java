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

	Optional<Number> version();

	Optional<Instant> issuedAt();

	Optional<Instant> expiresAt();

	Optional<Instant> notBefore();

	Optional<String> property(final String name);
}