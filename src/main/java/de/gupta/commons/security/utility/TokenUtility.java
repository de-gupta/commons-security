package de.gupta.commons.security.utility;

import io.jsonwebtoken.Claims;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public final class TokenUtility
{
	public static Set<String> audiencesOf(final Claims claims)
	{
		final Object rawAudience = claims.get("aud");
		if (rawAudience instanceof String audience)
		{
			return audience.isBlank() ? Set.of() : Set.of(audience);
		}
		if (rawAudience instanceof Collection<?> values)
		{
			return values.stream()
			             .filter(String.class::isInstance)
			             .map(String.class::cast)
			             .map(String::trim)
			             .filter(value -> !value.isEmpty())
			             .collect(Collectors.toUnmodifiableSet());
		}
		return Set.of();
	}

	private TokenUtility()
	{
	}
}