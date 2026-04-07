package de.gupta.commons.security.api;

import de.gupta.commons.security.adapter.TokenVerificationServiceFacade;
import de.gupta.commons.security.domain.model.VerificationResult;

final class HmacTokenVerifier implements TokenVerifier
{
	private final TokenVerificationServiceFacade facade;

	static TokenVerifier create(final TokenVerificationServiceFacade facade)
	{
		return new HmacTokenVerifier(facade);
	}

	@Override
	public VerificationResult verify(final String token)
	{
		return facade.verify(token);
	}

	private HmacTokenVerifier(final TokenVerificationServiceFacade facade)
	{
		this.facade = facade;
	}
}