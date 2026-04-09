package de.gupta.security.themis.adapter;

import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.application.service.VerificationContext;
import de.gupta.security.themis.application.service.VerificationRequest;
import de.gupta.security.themis.domain.model.VerificationKeyKind;

import java.time.Clock;
import java.util.Objects;

public final class EcVerificationRequestAdapter implements VerificationRequestAdapter
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
		return new EcVerificationRequestAdapter(policy, clock);
	}

	@Override
	public VerificationRequest adapt(final String token)
	{
		return VerificationRequest.of(
				token,
				VerificationContext.of(VerificationKeyKind.EC, policy, clock.instant()));
	}

	private EcVerificationRequestAdapter(final TokenVerificationPolicy policy, final Clock clock)
	{
		this.policy = policy;
		this.clock = clock;
	}
}
