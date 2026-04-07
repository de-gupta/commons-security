package de.gupta.security.themis.api;

import de.gupta.security.themis.domain.model.VerificationResult;

public interface TokenVerifier
{
	VerificationResult verify(final String token);
}