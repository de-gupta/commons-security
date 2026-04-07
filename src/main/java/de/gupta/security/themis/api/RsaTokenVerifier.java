package de.gupta.security.themis.api;

import de.gupta.security.themis.controller.TokenVerificationController;
import de.gupta.security.themis.domain.model.VerificationResult;

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