package de.gupta.commons.security.old.token.jwt.service;

import io.jsonwebtoken.JwtParser;

public final class JwtServices
{
	public static JwtService create(final JwtParser jwtParser, final String rolesClaim)
	{
		return new JwtServiceImpl(jwtParser, rolesClaim);
	}

	private JwtServices()
	{
	}
}