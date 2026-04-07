package de.gupta.commons.security.adapter;

import de.gupta.commons.security.application.service.TokenVerificationService;
import de.gupta.commons.security.domain.model.VerificationResult;

final class TokenVerificationServiceFacadeImpl implements TokenVerificationServiceFacade
{
	private final TokenVerificationService service;
	private final VerificationRequestAdapter adapter;

	static TokenVerificationServiceFacade create(final TokenVerificationService service,
	                                             final VerificationRequestAdapter adapter)
	{
		return new TokenVerificationServiceFacadeImpl(service, adapter);
	}

	@Override
	public VerificationResult verify(final String token)
	{
		return service.verifyToken(adapter.adapt(token));
	}

	private TokenVerificationServiceFacadeImpl(final TokenVerificationService service,
	                                           final VerificationRequestAdapter adapter)
	{
		this.service = service;
		this.adapter = adapter;
	}
}