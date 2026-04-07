package de.gupta.security.themis.api;

import de.gupta.security.themis.adapter.EcVerificationRequestAdapter;
import de.gupta.security.themis.adapter.TokenVerificationServiceFacadeFactory;
import de.gupta.security.themis.application.service.TokenVerificationServiceFactory;
import de.gupta.security.themis.controller.TokenVerificationControllerFactory;
import io.jsonwebtoken.Jwts;

import java.security.interfaces.ECPublicKey;
import java.util.Objects;

final class EcTokenVerifierFactory
{
	static TokenVerifier create(final TokenVerificationPolicy policy, final ECPublicKey issuerPublicKey)
	{
		Objects.requireNonNull(policy, "policy must not be null");
		Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");

		final var parser = Jwts.parser()
		                       .verifyWith(issuerPublicKey)
		                       .clockSkewSeconds(policy.clockSkew().toSeconds())
		                       .build();

		return EcTokenVerifier.create(
				TokenVerificationControllerFactory.create(
						TokenVerificationServiceFacadeFactory.create(
								TokenVerificationServiceFactory.create(parser),
								EcVerificationRequestAdapter.create(policy))));
	}

	private EcTokenVerifierFactory()
	{
	}
}