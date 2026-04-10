package de.gupta.security.themis.utility;

import de.gupta.aletheia.collection.cascade.Cascade;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import io.jsonwebtoken.Claims;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class TokenUtility
{
	public static Set<String> audiencesOf(final Claims claims)
	{
		return Cascade.beckon(audienceStreamOf(claims.get(Claims.AUDIENCE)))
		              .discern(String.class::isInstance)
		              .metamorphose(String.class::cast)
		              .metamorphose(String::trim)
		              .discern(StringSanitizationUtility::isNotBlank)
		              .coronate(s -> s.collect(Collectors.toUnmodifiableSet()), Set::of);
	}

	private static Stream<?> audienceStreamOf(final Object rawAudience)
	{
		return switch (rawAudience)
		{
			case String audience -> Stream.of(audience);
			case Collection<?> audiences -> audiences.stream();
			case null, default -> Stream.empty();
		};
	}

	private TokenUtility()
	{
	}
}