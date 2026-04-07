package de.gupta.commons.security.adapter;

import de.gupta.commons.security.application.service.TokenVerificationService;
import de.gupta.commons.security.domain.model.VerificationResult;

public final class TokenVerificationServiceFacadeImpl implements TokenVerificationServiceFacade
{
	private final TokenVerificationService service;

	@Override
	public VerificationResult verifyToken(final String token)
	{
		// TODO
//		service.verifyToken(adapter(token));
		return null;
	}

	private TokenVerificationServiceFacadeImpl(final TokenVerificationService service)
	{
		this.service = service;
	}
}