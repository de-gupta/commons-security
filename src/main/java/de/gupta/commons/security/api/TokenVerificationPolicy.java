package de.gupta.commons.security.api;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

public record TokenVerificationPolicy(Duration clockSkew, boolean requireSubject, Set<String> expectedAudiences,
                                      Optional<String> expectedIssuer)
{
	public static TokenVerificationPolicy of(final Duration clockSkew, final boolean requireSubject,
	                                         final Set<String> expectedAudiences, final Optional<String> expectedIssuer)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, Set.copyOf(expectedAudiences), expectedIssuer);
	}

	public static TokenVerificationPolicy of(final Duration clockSkew, final boolean requireSubject,
	                                         final Set<String> expectedAudiences)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, Set.copyOf(expectedAudiences), Optional.empty());
	}

	public static TokenVerificationPolicy of(final Duration clockSkew, final boolean requireSubject)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, Set.of(), Optional.empty());
	}

	public static TokenVerificationPolicy of(final Duration clockSkew)
	{
		return new TokenVerificationPolicy(clockSkew, false, Set.of(), Optional.empty());
	}

	public static TokenVerificationPolicy create()
	{
		return new TokenVerificationPolicy(Duration.ofSeconds(0), false, Set.of(), Optional.empty());
	}
}