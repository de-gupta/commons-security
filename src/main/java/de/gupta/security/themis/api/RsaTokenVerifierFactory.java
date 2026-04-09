package de.gupta.security.themis.api;

import de.gupta.security.themis.adapter.RsaVerificationRequestAdapter;
import de.gupta.security.themis.adapter.TokenVerificationServiceFacadeFactory;
import de.gupta.security.themis.application.service.TokenVerificationServiceFactory;
import de.gupta.security.themis.controller.TokenVerificationControllerFactory;
import io.jsonwebtoken.Jwts;

import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

final class RsaTokenVerifierFactory
{
	static TokenVerifier create(final TokenVerificationPolicy policy, final TokenClaimConfiguration configuration,
	                            final RSAPublicKey issuerPublicKey)
	{
		Objects.requireNonNull(policy, "policy must not be null");
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");

		final var parser = Jwts.parser()
		                       .verifyWith(issuerPublicKey)
		                       .clockSkewSeconds(policy.clockSkew().toSeconds())
		                       .build();

		return RsaTokenVerifier.create(
				TokenVerificationControllerFactory.create(
						TokenVerificationServiceFacadeFactory.create(
								TokenVerificationServiceFactory.create(parser),
								RsaVerificationRequestAdapter.create(policy, configuration))));
	}

	private RsaTokenVerifierFactory()
	{
	}
}