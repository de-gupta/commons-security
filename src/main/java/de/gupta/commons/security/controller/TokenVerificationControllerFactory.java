package de.gupta.commons.security.controller;

import de.gupta.commons.security.adapter.TokenVerificationServiceFacade;

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