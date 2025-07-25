package de.gupta.commons.security.token.jwt.filter;

import de.gupta.commons.security.token.jwt.service.JwtService;
import jakarta.servlet.Filter;

public final class FilterFactory
{
	public static Filter jwtFilter(final JwtService service)
	{
		return new JwtFilterImpl(service);
	}
}