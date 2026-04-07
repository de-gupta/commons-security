package de.gupta.security.themis.domain.model;

import java.util.Optional;

public record VerificationFailure(VerificationFailureReason reason, Optional<String> details)
		implements VerificationResult
{
	public static VerificationFailure of(VerificationFailureReason reason)
	{
		return new VerificationFailure(reason, Optional.empty());
	}
}