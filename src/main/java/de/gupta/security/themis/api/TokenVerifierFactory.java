package de.gupta.security.themis.api;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;

public final class TokenVerifierFactory
{
	public static TokenVerifier hmac(final TokenVerificationConfiguration configuration, final String issuerSecret)
	{
		return hmac(configuration, issuerSecret, Clock.systemUTC());
	}

	public static TokenVerifier hmac(final TokenVerificationConfiguration configuration,
	                                 final String issuerSecret,
	                                 final Clock clock)
	{
		return HmacTokenVerifierFactory.create(configuration, issuerSecret, clock);
	}

	public static TokenVerifier rsa(final TokenVerificationConfiguration configuration,
	                                final RSAPublicKey issuerPublicKey)
	{
		return rsa(configuration, issuerPublicKey, Clock.systemUTC());
	}

	public static TokenVerifier rsa(final TokenVerificationConfiguration configuration,
	                                final RSAPublicKey issuerPublicKey,
	                                final Clock clock)
	{
		return RsaTokenVerifierFactory.create(configuration, issuerPublicKey, clock);
	}

	public static TokenVerifier ec(final TokenVerificationConfiguration configuration,
	                               final ECPublicKey issuerPublicKey)
	{
		return ec(configuration, issuerPublicKey, Clock.systemUTC());
	}

	public static TokenVerifier ec(final TokenVerificationConfiguration configuration,
	                               final ECPublicKey issuerPublicKey,
	                               final Clock clock)
	{
		return EcTokenVerifierFactory.create(configuration, issuerPublicKey, clock);
	}

	private TokenVerifierFactory()
	{
	}
}
