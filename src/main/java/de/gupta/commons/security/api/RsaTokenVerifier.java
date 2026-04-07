package de.gupta.commons.security.api;

import de.gupta.commons.security.controller.TokenVerificationController;
import de.gupta.commons.security.domain.model.VerificationResult;

final class RsaTokenVerifier implements TokenVerifier
{
	private final TokenVerificationController controller;

	static TokenVerifier create(final TokenVerificationController controller)
	{
		return new RsaTokenVerifier(controller);
	}

	@Override
	public VerificationResult verify(final String token)
	{
		return controller.verify(token);
	}

	private RsaTokenVerifier(final TokenVerificationController controller)
	{
		this.controller = controller;
	}
}