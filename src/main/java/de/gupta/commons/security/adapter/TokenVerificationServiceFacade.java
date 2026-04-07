package de.gupta.commons.security.adapter;

import de.gupta.commons.security.domain.model.VerificationResult;

public interface TokenVerificationServiceFacade
{
	VerificationResult verifyToken(final String token);
}