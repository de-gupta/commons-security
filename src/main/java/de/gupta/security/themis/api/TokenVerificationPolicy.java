package de.gupta.security.themis.api;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

public record TokenVerificationPolicy(Duration clockSkew, boolean requireSubject, Set<String> expectedAudiences,
                                      Optional<String> expectedIssuer, String rolesClaimName, String versionClaimName)
{
	public static final String DEFAULT_ROLES_CLAIM_NAME = "roles";
	public static final String DEFAULT_VERSION_CLAIM_NAME = "ver";

	public static TokenVerificationPolicy of(final Duration clockSkew, final boolean requireSubject,
	                                         final Set<String> expectedAudiences, final Optional<String> expectedIssuer)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, Set.copyOf(expectedAudiences), expectedIssuer,
				DEFAULT_ROLES_CLAIM_NAME, DEFAULT_VERSION_CLAIM_NAME);
	}

	public static TokenVerificationPolicy of(final Duration clockSkew, final boolean requireSubject,
	                                         final Set<String> expectedAudiences)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, Set.copyOf(expectedAudiences), Optional.empty(),
				DEFAULT_ROLES_CLAIM_NAME, DEFAULT_VERSION_CLAIM_NAME);
	}

	public static TokenVerificationPolicy of(final Duration clockSkew, final boolean requireSubject)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, Set.of(), Optional.empty(),
				DEFAULT_ROLES_CLAIM_NAME, DEFAULT_VERSION_CLAIM_NAME);
	}

	public static TokenVerificationPolicy of(final Duration clockSkew)
	{
		return new TokenVerificationPolicy(clockSkew, false, Set.of(), Optional.empty(),
				DEFAULT_ROLES_CLAIM_NAME, DEFAULT_VERSION_CLAIM_NAME);
	}

	public static TokenVerificationPolicy create()
	{
		return new TokenVerificationPolicy(Duration.ofSeconds(0), false, Set.of(), Optional.empty(),
				DEFAULT_ROLES_CLAIM_NAME, DEFAULT_VERSION_CLAIM_NAME);
	}

	public TokenVerificationPolicy withRolesClaimName(final String rolesClaimName)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, expectedAudiences, expectedIssuer,
				rolesClaimName, versionClaimName);
	}

	public TokenVerificationPolicy withVersionClaimName(final String versionClaimName)
	{
		return new TokenVerificationPolicy(clockSkew, requireSubject, expectedAudiences, expectedIssuer,
				rolesClaimName, versionClaimName);
	}
}