package de.gupta.security.themis.api;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record TokenVerificationPolicy(Duration clockSkew,
                                      boolean requireSubject,
                                      Set<String> expectedAudiences,
                                      Optional<String> expectedIssuer)
{
	public static TokenVerificationPolicy of(final Duration clockSkew,
	                                         final boolean requireSubject,
	                                         final Set<String> expectedAudiences,
	                                         final Optional<String> expectedIssuer)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, Set.copyOf(expectedAudiences), expectedIssuer);
	}

	public static TokenVerificationPolicy of(final Duration clockSkew,
	                                         final boolean requireSubject,
	                                         final Set<String> expectedAudiences)
	{
		return of(clockSkew, requireSubject, expectedAudiences, Optional.empty());
	}

	public static TokenVerificationPolicy of(final Duration clockSkew, final boolean requireSubject)
	{
		return of(clockSkew, requireSubject, Set.of(), Optional.empty());
	}

	public static TokenVerificationPolicy of(final Duration clockSkew)
	{
		return of(clockSkew, false, Set.of(), Optional.empty());
	}

	public static TokenVerificationPolicy create()
	{
		return of(Duration.ofSeconds(0));
	}

	public TokenVerificationPolicy
	{
		Objects.requireNonNull(clockSkew, "clockSkew must not be null");
		if (clockSkew.isNegative())
		{
			throw new IllegalArgumentException("clockSkew must not be negative");
		}
		expectedAudiences = Set.copyOf(Objects.requireNonNull(expectedAudiences, "expectedAudiences must not be null"));
		Objects.requireNonNull(expectedIssuer, "expectedIssuer must not be null");
	}
}