package de.gupta.commons.security.api;

public final class TokenVerifierFactory
{
	public static TokenVerifier hmac(final TokenVerificationPolicy policy, final String issuerSecret)
	{
		return HmacTokenVerifierFactory.create(policy, issuerSecret);
	}

	private TokenVerifierFactory()
	{
	}
}