package de.gupta.security.themis.adapter;

import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.application.service.VerificationRequest;

import java.util.Objects;

public final class ConfiguredVerificationRequestAdapter implements VerificationRequestAdapter
{
	private final TokenVerificationConfiguration configuration;

	public static VerificationRequestAdapter create(final TokenVerificationConfiguration configuration)
	{
		Objects.requireNonNull(configuration, "configuration must not be null");
		return new ConfiguredVerificationRequestAdapter(configuration);
	}

	@Override
	public VerificationRequest adapt(final String token)
	{
		return VerificationRequest.of(token, configuration);
	}

	private ConfiguredVerificationRequestAdapter(final TokenVerificationConfiguration configuration)
	{
		this.configuration = configuration;
	}
}
