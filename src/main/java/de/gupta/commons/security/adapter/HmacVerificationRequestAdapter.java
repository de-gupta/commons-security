package de.gupta.commons.security.adapter;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.application.service.VerificationContext;
import de.gupta.commons.security.application.service.VerificationRequest;
import de.gupta.commons.security.domain.model.VerificationKeyKind;

import java.time.Instant;
import java.util.Objects;

public final class HmacVerificationRequestAdapter implements VerificationRequestAdapter
{
	private final TokenVerificationPolicy policy;

	public static VerificationRequestAdapter create(final TokenVerificationPolicy policy)
	{
		Objects.requireNonNull(policy, "policy must not be null");
		return new HmacVerificationRequestAdapter(policy);
	}

	@Override
	public VerificationRequest adapt(final String token)
	{
		return VerificationRequest.of(
				token,
				VerificationContext.of(VerificationKeyKind.HMAC, policy, Instant.now()));
	}

	private HmacVerificationRequestAdapter(final TokenVerificationPolicy policy)
	{
		this.policy = policy;
	}
}