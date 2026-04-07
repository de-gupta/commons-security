package de.gupta.security.themis.adapter;

import de.gupta.security.themis.application.service.VerificationRequest;

@FunctionalInterface
public interface VerificationRequestAdapter
{
	VerificationRequest adapt(String token);
}