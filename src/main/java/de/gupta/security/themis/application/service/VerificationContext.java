package de.gupta.security.themis.application.service;

import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.domain.model.VerificationKeyKind;

import java.time.Instant;
import java.util.Objects;

public record VerificationContext(VerificationKeyKind keyKind,
                                  TokenVerificationConfiguration configuration,
                                  Instant verificationRequestedAt)
{
	public static VerificationContext of(final VerificationKeyKind keyKind,
	                                     final TokenVerificationConfiguration configuration,
	                                     final Instant verificationRequestedAt)
	{
		Objects.requireNonNull(keyKind, "keyKind must not be null");
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(verificationRequestedAt, "verificationRequestedAt must not be null");
		return new VerificationContext(keyKind, configuration, verificationRequestedAt);
	}
}
