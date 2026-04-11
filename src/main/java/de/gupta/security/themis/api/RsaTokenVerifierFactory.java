package de.gupta.security.themis.api;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
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

		return ParserConfiguredTokenVerifierFactorySupport.create(configuration, clock,
				builder -> builder.verifyWith(issuerPublicKey));
	}

	private RsaTokenVerifierFactory()
	{
	}
}