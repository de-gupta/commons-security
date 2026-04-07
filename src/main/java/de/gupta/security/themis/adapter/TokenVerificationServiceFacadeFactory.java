package de.gupta.security.themis.adapter;

import de.gupta.security.themis.application.service.TokenVerificationService;

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