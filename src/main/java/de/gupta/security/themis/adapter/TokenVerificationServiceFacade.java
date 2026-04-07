package de.gupta.security.themis.adapter;

import de.gupta.security.themis.domain.model.VerificationResult;

public interface TokenVerificationServiceFacade
{
	VerificationResult verify(final String token);
}