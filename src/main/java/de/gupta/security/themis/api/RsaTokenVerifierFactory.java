package de.gupta.security.themis.api;

import de.gupta.security.themis.adapter.ConfiguredVerificationRequestAdapter;
import de.gupta.security.themis.adapter.TokenVerificationServiceFacadeFactory;
import de.gupta.security.themis.application.service.TokenVerificationServiceFactory;
import de.gupta.security.themis.controller.TokenVerificationControllerFactory;
import io.jsonwebtoken.Jwts;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Date;
import java.util.Objects;

final class RsaTokenVerifierFactory
{
	static TokenVerifier create(final TokenVerificationConfiguration configuration, final RSAPublicKey issuerPublicKey)
	{
		return create(configuration, issuerPublicKey, Clock.systemUTC());
	}

	static TokenVerifier create(final TokenVerificationConfiguration configuration,
	                            final RSAPublicKey issuerPublicKey,
	                            final Clock clock)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		Objects.requireNonNull(clock, "clock must not be null");

		final var parser = Jwts.parser()
		                       .verifyWith(issuerPublicKey)
		                       .clock(() -> Date.from(clock.instant()))
		                       .clockSkewSeconds(configuration.policy().clockSkew().toSeconds())
		                       .build();

		return ConfiguredTokenVerifier.create(
				TokenVerificationControllerFactory.create(
						TokenVerificationServiceFacadeFactory.create(
								TokenVerificationServiceFactory.create(parser),
								ConfiguredVerificationRequestAdapter.create(configuration, clock))));
	}

	private RsaTokenVerifierFactory()
	{
	}
}
