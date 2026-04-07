package de.gupta.security.themis.application.service;

import java.util.Objects;

public record VerificationRequest(String token, VerificationContext context)
{
	public static VerificationRequest of(final String token, final VerificationContext context)
	{
		Objects.requireNonNull(token, "token must not be null");
		Objects.requireNonNull(context, "context must not be null");
		return new VerificationRequest(token, context);
	}
}