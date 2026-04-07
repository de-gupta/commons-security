package de.gupta.commons.security.api;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public final class TokenVerifierFactory
{
	public static TokenVerifier hmac(final TokenVerificationPolicy policy, final String issuerSecret)
	{
		return HmacTokenVerifierFactory.create(policy, issuerSecret);
	}

	public static TokenVerifier rsa(final TokenVerificationPolicy policy, final RSAPublicKey issuerPublicKey)
	{
		return RsaTokenVerifierFactory.create(policy, issuerPublicKey);
	}

	public static TokenVerifier ec(final TokenVerificationPolicy policy, final ECPublicKey issuerPublicKey)
	{
		return EcTokenVerifierFactory.create(policy, issuerPublicKey);
	}

	private TokenVerifierFactory()
	{
	}
}
