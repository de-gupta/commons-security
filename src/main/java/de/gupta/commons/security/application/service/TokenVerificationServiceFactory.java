package de.gupta.commons.security.application.service;

import io.jsonwebtoken.JwtParser;

public final class TokenVerificationServiceFactory
{
	public static TokenVerificationService create(final JwtParser jwtParser)
	{
		return TokenVerificationServiceImpl.create(jwtParser);
	}

	private TokenVerificationServiceFactory()
	{
	}
}
