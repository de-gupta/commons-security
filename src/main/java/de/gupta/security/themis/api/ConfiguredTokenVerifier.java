package de.gupta.security.themis.api;

import de.gupta.security.themis.application.service.TokenVerificationService;
import de.gupta.security.themis.domain.model.VerificationResult;

final class ConfiguredTokenVerifier implements TokenVerifier
{
	private final TokenVerificationConfiguration configuration;
	private final TokenVerificationService service;

	static TokenVerifier create(final TokenVerificationConfiguration configuration,
	                            final TokenVerificationService service)
	{
		return new ConfiguredTokenVerifier(configuration, service);
	}

	@Override
	public VerificationResult verify(final String token)
	{
		return service.verifyToken(token, configuration);
	}

	private ConfiguredTokenVerifier(final TokenVerificationConfiguration configuration,
	                                final TokenVerificationService service)
	{
		this.configuration = configuration;
		this.service = service;
	}
}