package de.gupta.security.themis.api;

import de.gupta.security.themis.controller.TokenVerificationController;
import de.gupta.security.themis.domain.model.VerificationResult;

final class ConfiguredTokenVerifier implements TokenVerifier
{
	private final TokenVerificationController controller;

	static TokenVerifier create(final TokenVerificationController controller)
	{
		return new ConfiguredTokenVerifier(controller);
	}

	@Override
	public VerificationResult verify(final String token)
	{
		return controller.verify(token);
	}

	private ConfiguredTokenVerifier(final TokenVerificationController controller)
	{
		this.controller = controller;
	}
}
