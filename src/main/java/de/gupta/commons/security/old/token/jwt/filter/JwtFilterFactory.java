package de.gupta.commons.security.old.token.jwt.filter;

import de.gupta.commons.security.old.token.jwt.service.JwtService;

public final class JwtFilterFactory
{
	public static JwtFilter create(final JwtService jwtService)
	{
		return new JwtFilterImpl(jwtService);
	}

	private JwtFilterFactory()
	{
	}
}