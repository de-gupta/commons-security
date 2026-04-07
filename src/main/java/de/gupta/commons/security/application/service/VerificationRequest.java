package de.gupta.commons.security.application.service;

public record VerificationRequest(String token, VerificationContext context)
{
}