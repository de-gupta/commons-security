package de.gupta.commons.security.adapter;

import de.gupta.commons.security.application.service.TokenVerificationService;

public final class TokenVerificationServiceFacadeFactory
{
	public static TokenVerificationServiceFacade create(final TokenVerificationService service,
	                                                    final VerificationRequestAdapter adapter)
	{
		return TokenVerificationServiceFacadeImpl.create(service, adapter);
	}

	private TokenVerificationServiceFacadeFactory()
	{
	}
}