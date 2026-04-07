package de.gupta.commons.security.application.service;

public record VerificationContext()
{
	public static VerificationContext create()
	{
		return new VerificationContext();
	}
}
