package de.gupta.commons.security.domain.model;

public record VerificationSuccess(NormalizedToken token) implements VerificationResult
{
}