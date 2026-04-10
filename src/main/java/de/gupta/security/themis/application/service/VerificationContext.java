package de.gupta.security.themis.application.service;

import de.gupta.security.themis.api.TokenVerificationConfiguration;

import java.time.Instant;
import java.util.Objects;

public record VerificationContext(TokenVerificationConfiguration configuration,
                                  Instant verificationRequestedAt)
{
	public static VerificationContext of(final TokenVerificationConfiguration configuration,
	                                     final Instant verificationRequestedAt)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(verificationRequestedAt, "verificationRequestedAt must not be null");
		return new VerificationContext(configuration, verificationRequestedAt);
	}
}
