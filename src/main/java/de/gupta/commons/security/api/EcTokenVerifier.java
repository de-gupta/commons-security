package de.gupta.commons.security.api;

import de.gupta.commons.security.controller.TokenVerificationController;
import de.gupta.commons.security.domain.model.VerificationResult;

final class EcTokenVerifier implements TokenVerifier
{
	private final TokenVerificationController controller;

	static TokenVerifier create(final TokenVerificationController controller)
	{
		return new EcTokenVerifier(controller);
	}

	@Override
	public VerificationResult verify(final String token)
	{
		return controller.verify(token);
	}

	private EcTokenVerifier(final TokenVerificationController controller)
	{
		this.controller = controller;
	}
}
