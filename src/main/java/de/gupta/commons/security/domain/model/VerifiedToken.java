package de.gupta.commons.security.domain.model;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

public interface VerifiedToken
{
	String rawToken();

	String subject();

	Optional<String> issuer();

	Set<String> audiences();

	Optional<Instant> issuedAt();

	Optional<Instant> expiresAt();

	Optional<String> stringClaim(String name);

	Set<String> stringListClaim(String name);

	Optional<Long> longClaim(String name);
}