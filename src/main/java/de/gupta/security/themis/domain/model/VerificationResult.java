package de.gupta.security.themis.domain.model;

public sealed interface VerificationResult
		permits VerificationSuccess, VerificationFailure
{
}