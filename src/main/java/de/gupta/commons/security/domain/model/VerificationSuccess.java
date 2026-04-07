package de.gupta.commons.security.domain.model;

public record VerificationSuccess(VerifiedToken token) implements VerificationResult
{
}