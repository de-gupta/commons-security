package de.gupta.commons.security.adapter;

import de.gupta.commons.security.application.service.VerificationRequest;

@FunctionalInterface
public interface VerificationRequestAdapter
{
	VerificationRequest adapt(String token);
}