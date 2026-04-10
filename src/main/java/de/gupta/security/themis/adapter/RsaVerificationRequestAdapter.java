package de.gupta.security.themis.adapter;

import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.application.service.VerificationContext;
import de.gupta.security.themis.application.service.VerificationRequest;
import de.gupta.security.themis.domain.model.VerificationKeyKind;

import java.time.Clock;
import java.util.Objects;

public final class RsaVerificationRequestAdapter implements VerificationRequestAdapter
{
	private final TokenVerificationConfiguration configuration;
	private final Clock clock;

	public static VerificationRequestAdapter create(final TokenVerificationConfiguration configuration)
	{
		return create(configuration, Clock.systemUTC());
	}

	public static VerificationRequestAdapter create(final TokenVerificationConfiguration configuration,
	                                                final Clock clock)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		Objects.requireNonNull(clock, "clock must not be null");
		return new RsaVerificationRequestAdapter(configuration, clock);
	}

	@Override
	public VerificationRequest adapt(final String token)
	{
		return VerificationRequest.of(
				token,
				VerificationContext.of(VerificationKeyKind.RSA, configuration, clock.instant()));
	}

	private RsaVerificationRequestAdapter(final TokenVerificationConfiguration configuration, final Clock clock)
	{
		this.configuration = configuration;
		this.clock = clock;
	}
}
