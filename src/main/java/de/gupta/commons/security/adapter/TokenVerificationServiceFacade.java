package de.gupta.commons.security.adapter;

import de.gupta.commons.security.domain.model.VerificationResult;

public interface TokenVerificationServiceFacade
{
	VerificationResult verify(final String token);
}