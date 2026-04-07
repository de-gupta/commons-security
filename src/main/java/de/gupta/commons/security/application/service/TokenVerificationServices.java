package de.gupta.commons.security.application.service;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import io.jsonwebtoken.JwtParser;

public final class TokenVerificationServices
{
	public static TokenVerificationService create(final JwtParser jwtParser, final TokenVerificationPolicy policy)
	{
		return TokenVerificationServiceImpl.create(jwtParser, policy);
	}

	private TokenVerificationServices()
	{
	}
}
