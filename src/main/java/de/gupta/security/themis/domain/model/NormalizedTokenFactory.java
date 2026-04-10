package de.gupta.security.themis.domain.model;

import io.jsonwebtoken.Claims;

public final class NormalizedTokenFactory
{
	public static NormalizedToken of(final String rawToken, final Claims claims, final String rolesClaimName,
	                                 final String versionClaimName)
	{
		return DefaultNormalizedToken.of(rawToken, claims, rolesClaimName, versionClaimName);
	}
}