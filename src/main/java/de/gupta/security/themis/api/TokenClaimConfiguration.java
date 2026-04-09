package de.gupta.security.themis.api;

public record TokenClaimConfiguration(String rolesClaimName, String versionClaimName)
{
	public static final String DEFAULT_ROLES_CLAIM_NAME = "roles";
	public static final String DEFAULT_VERSION_CLAIM_NAME = "ver";

	public static TokenClaimConfiguration create()
	{
		return new TokenClaimConfiguration(DEFAULT_ROLES_CLAIM_NAME, DEFAULT_VERSION_CLAIM_NAME);
	}

	public TokenClaimConfiguration withRolesClaimName(final String rolesClaimName)
	{
		return new TokenClaimConfiguration(rolesClaimName, versionClaimName);
	}

	public TokenClaimConfiguration withVersionClaimName(final String versionClaimName)
	{
		return new TokenClaimConfiguration(rolesClaimName, versionClaimName);
	}
}