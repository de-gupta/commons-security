package de.gupta.security.themis.adapter;

import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.application.service.VerificationContext;
import de.gupta.security.themis.application.service.VerificationRequest;
import de.gupta.security.themis.domain.model.VerificationKeyKind;

import java.time.Clock;
import java.util.Objects;

public final class RsaVerificationRequestAdapter implements VerificationRequestAdapter
{
	private final TokenVerificationPolicy policy;
	private final Clock clock;

	public static VerificationRequestAdapter create(final TokenVerificationPolicy policy)
	{
		return create(policy, Clock.systemUTC());
	}

	public static VerificationRequestAdapter create(final TokenVerificationPolicy policy, final Clock clock)
	{
		Objects.requireNonNull(policy, "policy must not be null");
		Objects.requireNonNull(clock, "clock must not be null");
		return new RsaVerificationRequestAdapter(policy, clock);
	}

	@Override
	public VerificationRequest adapt(final String token)
	{
		return VerificationRequest.of(
				token,
				VerificationContext.of(VerificationKeyKind.RSA, policy, clock.instant()));
	}

	private RsaVerificationRequestAdapter(final TokenVerificationPolicy policy, final Clock clock)
	{
		this.policy = policy;
		this.clock = clock;
	}
}
