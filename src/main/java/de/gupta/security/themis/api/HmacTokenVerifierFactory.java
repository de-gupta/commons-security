package de.gupta.security.themis.api;

import de.gupta.security.themis.adapter.HmacVerificationRequestAdapter;
import de.gupta.security.themis.adapter.TokenVerificationServiceFacadeFactory;
import de.gupta.security.themis.application.service.TokenVerificationServiceFactory;
import de.gupta.security.themis.controller.TokenVerificationControllerFactory;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

final class HmacTokenVerifierFactory
{
	public static TokenVerifier create(final TokenVerificationPolicy policy,
	                                   final TokenClaimConfiguration configuration,
	                                   final String issuerSecret)
	{
		Objects.requireNonNull(policy, "policy must not be null");
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(issuerSecret, "issuerSecret must not be null");

		final var parser = Jwts.parser()
		                       .verifyWith(Keys.hmacShaKeyFor(issuerSecret.getBytes(StandardCharsets.UTF_8)))
		                       .clockSkewSeconds(policy.clockSkew().toSeconds())
		                       .build();

		return HmacTokenVerifier.create(
				TokenVerificationControllerFactory.create(
						TokenVerificationServiceFacadeFactory.create(
								TokenVerificationServiceFactory.create(parser),
								HmacVerificationRequestAdapter.create(policy, configuration))));
	}

	private HmacTokenVerifierFactory()
	{
	}
}