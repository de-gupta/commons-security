package de.gupta.security.themis.application.service;

import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.domain.model.VerificationResult;

public interface TokenVerificationService
{
	VerificationResult verifyToken(final String token, final TokenVerificationConfiguration configuration);
}