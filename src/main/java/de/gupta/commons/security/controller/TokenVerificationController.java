package de.gupta.commons.security.controller;

import de.gupta.commons.security.domain.model.VerificationResult;

public interface TokenVerificationController
{
	VerificationResult verify(String token);
}