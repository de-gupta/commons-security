package de.gupta.security.themis.api;

import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Objects;

final class HmacTokenVerifierFactory
{
	static TokenVerifier create(final TokenVerificationConfiguration configuration, final String issuerSecret)
	{
		return create(configuration, issuerSecret, Clock.systemUTC());
	}

	static TokenVerifier create(final TokenVerificationConfiguration configuration,
	                            final String issuerSecret,
	                            final Clock clock)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(issuerSecret, "issuerSecret must not be null");
		Objects.requireNonNull(clock, "clock must not be null");

		return ParserConfiguredTokenVerifierFactorySupport.create(configuration, clock,
				builder -> builder.verifyWith(Keys.hmacShaKeyFor(issuerSecret.getBytes(StandardCharsets.UTF_8))));
	}

	private HmacTokenVerifierFactory()
	{
	}
}