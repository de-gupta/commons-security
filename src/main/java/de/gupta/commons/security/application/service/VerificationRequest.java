package de.gupta.commons.security.application.service;

public record VerificationRequest(String token, VerificationContext context)
{
	public static VerificationRequest of(final String token, final VerificationContext context)
	{
		return new VerificationRequest(token, context);
	}
}
