package de.gupta.security.themis.api;

import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.util.Objects;

final class EcTokenVerifierFactory
{
	static TokenVerifier create(final TokenVerificationConfiguration configuration, final ECPublicKey issuerPublicKey)
	{
		return create(configuration, issuerPublicKey, Clock.systemUTC());
	}

	static TokenVerifier create(final TokenVerificationConfiguration configuration,
	                            final ECPublicKey issuerPublicKey,
	                            final Clock clock)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(issuerPublicKey, "issuerPublicKey must not be null");
		Objects.requireNonNull(clock, "clock must not be null");

		return ParserConfiguredTokenVerifierFactorySupport.create(configuration, clock,
				builder -> builder.verifyWith(issuerPublicKey));
	}

	private EcTokenVerifierFactory()
	{
	}
}