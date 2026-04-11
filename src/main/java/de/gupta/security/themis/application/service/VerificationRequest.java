package de.gupta.security.themis.application.service;

import de.gupta.security.themis.api.TokenVerificationConfiguration;

import java.util.Objects;

public record VerificationRequest(String token, TokenVerificationConfiguration configuration)
{
	public static VerificationRequest of(final String token, final TokenVerificationConfiguration configuration)
	{
		Objects.requireNonNull(token, "token must not be null");
		Objects.requireNonNull(configuration, "configuration must not be null");
		return new VerificationRequest(token, configuration);
	}
}
