package de.gupta.security.themis.adapter;

import de.gupta.security.themis.application.service.TokenVerificationService;
import de.gupta.security.themis.domain.model.VerificationResult;

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