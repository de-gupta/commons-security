package de.gupta.security.themis.controller;

import de.gupta.security.themis.adapter.TokenVerificationServiceFacade;

public final class TokenVerificationControllerFactory
{
	public static TokenVerificationController create(final TokenVerificationServiceFacade facade)
	{
		return TokenVerificationControllerImpl.create(facade);
	}

	private TokenVerificationControllerFactory()
	{
	}
}