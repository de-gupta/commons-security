package de.gupta.commons.security.api;

import de.gupta.commons.security.adapter.TokenVerificationServiceFacadeFactory;
import de.gupta.commons.security.adapter.VerificationRequestAdapter;
import de.gupta.commons.security.application.service.TokenVerificationServiceFactory;
import de.gupta.commons.security.application.service.VerificationContext;
import de.gupta.commons.security.application.service.VerificationRequest;
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
		final VerificationRequestAdapter adapter =
				token -> VerificationRequest.of(token, VerificationContext.create());

		return HmacTokenVerifier.create(
				TokenVerificationServiceFacadeFactory.create(
						TokenVerificationServiceFactory.create(parser, policy), adapter));
	}

	private HmacTokenVerifierFactory()
	{
	}
}