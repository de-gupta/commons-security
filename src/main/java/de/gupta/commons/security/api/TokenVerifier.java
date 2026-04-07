package de.gupta.commons.security.api;

import de.gupta.commons.security.domain.model.VerificationResult;

public interface TokenVerifier
{
	VerificationResult verify(final String token);
}