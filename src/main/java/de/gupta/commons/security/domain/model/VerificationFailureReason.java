package de.gupta.commons.security.domain.model;

public enum VerificationFailureReason
{
	MALFORMED,
	INVALID_SIGNATURE,
	EXPIRED,
	NOT_YET_VALID,
	MISSING_SUBJECT,
	INVALID_ISSUER,
	INVALID_AUDIENCE,
	UNSUPPORTED
}