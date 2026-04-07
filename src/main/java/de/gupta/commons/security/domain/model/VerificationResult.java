package de.gupta.commons.security.domain.model;

public sealed interface VerificationResult
		permits VerificationSuccess, VerificationFailure
{
}