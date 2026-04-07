package de.gupta.security.themis.adapter;

import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.application.service.VerificationContext;
import de.gupta.security.themis.application.service.VerificationRequest;
import de.gupta.security.themis.domain.model.VerificationKeyKind;

import java.time.Instant;
import java.util.Objects;

public final class RsaVerificationRequestAdapter implements VerificationRequestAdapter
{
	private final TokenVerificationPolicy policy;

	public static VerificationRequestAdapter create(final TokenVerificationPolicy policy)
	{
		Objects.requireNonNull(policy, "policy must not be null");
		return new RsaVerificationRequestAdapter(policy);
	}

	@Override
	public VerificationRequest adapt(final String token)
	{
		return VerificationRequest.of(
				token,
				VerificationContext.of(VerificationKeyKind.RSA, policy, Instant.now()));
	}

	private RsaVerificationRequestAdapter(final TokenVerificationPolicy policy)
	{
		this.policy = policy;
	}
}