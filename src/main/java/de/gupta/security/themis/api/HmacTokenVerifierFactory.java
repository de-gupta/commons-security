package de.gupta.security.themis.api;

import de.gupta.security.themis.adapter.ConfiguredVerificationRequestAdapter;
import de.gupta.security.themis.adapter.TokenVerificationServiceFacadeFactory;
import de.gupta.security.themis.application.service.TokenVerificationServiceFactory;
import de.gupta.security.themis.controller.TokenVerificationControllerFactory;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Date;
import java.util.Objects;

final class HmacTokenVerifierFactory
{
	public static TokenVerifier create(final TokenVerificationConfiguration configuration, final String issuerSecret)
	{
		return create(configuration, issuerSecret, Clock.systemUTC());
	}

	public static TokenVerifier create(final TokenVerificationConfiguration configuration,
	                                   final String issuerSecret,
	                                   final Clock clock)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(issuerSecret, "issuerSecret must not be null");
		Objects.requireNonNull(clock, "clock must not be null");

		final var parser = Jwts.parser()
		                       .verifyWith(Keys.hmacShaKeyFor(issuerSecret.getBytes(StandardCharsets.UTF_8)))
		                       .clock(() -> Date.from(clock.instant()))
		                       .clockSkewSeconds(configuration.policy().clockSkew().toSeconds())
		                       .build();

		return ConfiguredTokenVerifier.create(
				TokenVerificationControllerFactory.create(
						TokenVerificationServiceFacadeFactory.create(
								TokenVerificationServiceFactory.create(parser),
								ConfiguredVerificationRequestAdapter.create(configuration, clock))));
	}

	private HmacTokenVerifierFactory()
	{
	}
}
