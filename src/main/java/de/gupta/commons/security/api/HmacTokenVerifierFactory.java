package de.gupta.commons.security.api;

import de.gupta.commons.security.adapter.TokenVerificationServiceFacadeFactory;
import de.gupta.commons.security.application.service.TokenVerificationServices;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

final class HmacTokenVerifierFactory
{
	public static TokenVerifier create(final TokenVerificationPolicy policy, final String issuerSecret)
	{
		Objects.requireNonNull(policy, "policy must not be null");
		Objects.requireNonNull(issuerSecret, "issuerSecret must not be null");

		final var parser = Jwts.parser()
		                       .verifyWith(Keys.hmacShaKeyFor(issuerSecret.getBytes(StandardCharsets.UTF_8)))
		                       .clockSkewSeconds(policy.clockSkew().toSeconds())
		                       .build();

		// TODO: Adapter should be created and passed
		return HmacTokenVerifier.create(
				TokenVerificationServiceFacadeFactory.create(
						TokenVerificationServices.create(parser, policy), null));
	}

	private HmacTokenVerifierFactory()
	{
	}
}