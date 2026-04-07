package de.gupta.commons.security.application.service;

import de.gupta.commons.security.domain.model.VerificationResult;

public interface TokenVerificationService
{
	VerificationResult verifyToken(final VerificationRequest request);
}