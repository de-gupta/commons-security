package de.gupta.security.themis.api;

import java.util.Objects;

public record TokenVerificationConfiguration(TokenVerificationPolicy policy,
                                             String rolesClaimName,
                                             String versionClaimName)
{
	public static final String DEFAULT_ROLES_CLAIM_NAME = "roles";
	public static final String DEFAULT_VERSION_CLAIM_NAME = "ver";

	public static TokenVerificationConfiguration of(final TokenVerificationPolicy policy,
	                                                final String rolesClaimName,
	                                                final String versionClaimName)
	{
		return new TokenVerificationConfiguration(policy, rolesClaimName, versionClaimName);
	}

	public static TokenVerificationConfiguration of(final TokenVerificationPolicy policy)
	{
		return new TokenVerificationConfiguration(policy, DEFAULT_ROLES_CLAIM_NAME, DEFAULT_VERSION_CLAIM_NAME);
	}

	public TokenVerificationConfiguration
	{
		Objects.requireNonNull(policy, "policy must not be null");
		Objects.requireNonNull(rolesClaimName, "rolesClaimName must not be null");
		if (rolesClaimName.isBlank())
		{
			throw new IllegalArgumentException("rolesClaimName must not be blank");
		}
		Objects.requireNonNull(versionClaimName, "versionClaimName must not be null");
		if (versionClaimName.isBlank())
		{
			throw new IllegalArgumentException("versionClaimName must not be blank");
		}
	}
}