package de.gupta.commons.security.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security")
public final class SecurityConfigurationProperties
{
	private String jwtSecret;

	public String getJwtSecret()
	{
		return jwtSecret;
	}

	public void setJwtSecret(final String jwtSecret)
	{
		this.jwtSecret = jwtSecret;
	}
}