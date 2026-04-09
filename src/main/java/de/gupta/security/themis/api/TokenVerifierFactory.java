package de.gupta.security.themis.api;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public final class TokenVerifierFactory
{
	public static TokenVerifier hmac(final TokenVerificationPolicy policy, final TokenClaimConfiguration configuration,
	                                 final String issuerSecret)
	{
		return HmacTokenVerifierFactory.create(policy, configuration, issuerSecret);
	}

	public static TokenVerifier rsa(final TokenVerificationPolicy policy, final TokenClaimConfiguration configuration,
	                                final RSAPublicKey issuerPublicKey)
	{
		return RsaTokenVerifierFactory.create(policy, configuration, issuerPublicKey);
	}

	public static TokenVerifier ec(final TokenVerificationPolicy policy, final TokenClaimConfiguration configuration,
	                               final ECPublicKey issuerPublicKey)
	{
		return EcTokenVerifierFactory.create(policy, configuration, issuerPublicKey);
	}

	private TokenVerifierFactory()
	{
	}
}