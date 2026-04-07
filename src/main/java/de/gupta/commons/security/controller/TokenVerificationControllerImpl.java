package de.gupta.commons.security.controller;

import de.gupta.commons.security.adapter.TokenVerificationServiceFacade;
import de.gupta.commons.security.domain.model.VerificationResult;

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