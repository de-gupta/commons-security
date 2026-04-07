package de.gupta.security.themis.controller;

import de.gupta.security.themis.domain.model.VerificationResult;

public interface TokenVerificationController
{
	VerificationResult verify(String token);
}