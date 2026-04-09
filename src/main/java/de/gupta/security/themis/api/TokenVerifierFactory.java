package de.gupta.security.themis.api;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;

public final class TokenVerifierFactory
{
	public static TokenVerifier hmac(final TokenVerificationPolicy policy, final String issuerSecret)
	{
		return hmac(policy, issuerSecret, Clock.systemUTC());
	}

	public static TokenVerifier hmac(final TokenVerificationPolicy policy,
	                                 final String issuerSecret,
	                                 final Clock clock)
	{
		return HmacTokenVerifierFactory.create(policy, issuerSecret, clock);
	}

	public static TokenVerifier rsa(final TokenVerificationPolicy policy, final RSAPublicKey issuerPublicKey)
	{
		return rsa(policy, issuerPublicKey, Clock.systemUTC());
	}

	public static TokenVerifier rsa(final TokenVerificationPolicy policy,
	                                final RSAPublicKey issuerPublicKey,
	                                final Clock clock)
	{
		return RsaTokenVerifierFactory.create(policy, issuerPublicKey, clock);
	}

	public static TokenVerifier ec(final TokenVerificationPolicy policy, final ECPublicKey issuerPublicKey)
	{
		return ec(policy, issuerPublicKey, Clock.systemUTC());
	}

	public static TokenVerifier ec(final TokenVerificationPolicy policy,
	                               final ECPublicKey issuerPublicKey,
	                               final Clock clock)
	{
		return EcTokenVerifierFactory.create(policy, issuerPublicKey, clock);
	}

	private TokenVerifierFactory()
	{
	}
}
