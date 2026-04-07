package de.gupta.security.themis.domain.model;

public record VerificationSuccess(NormalizedToken token) implements VerificationResult
{
	public static VerificationSuccess of(NormalizedToken token)
	{
		return new VerificationSuccess(token);
	}
}