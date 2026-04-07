package de.gupta.security.themis.controller;

import de.gupta.security.themis.adapter.TokenVerificationServiceFacade;
import de.gupta.security.themis.domain.model.VerificationResult;

final class TokenVerificationControllerImpl implements TokenVerificationController
{
	private final TokenVerificationServiceFacade facade;

	static TokenVerificationController create(final TokenVerificationServiceFacade facade)
	{
		return new TokenVerificationControllerImpl(facade);
	}

	@Override
	public VerificationResult verify(final String token)
	{
		return facade.verify(token);
	}

	private TokenVerificationControllerImpl(final TokenVerificationServiceFacade facade)
	{
		this.facade = facade;
	}
}