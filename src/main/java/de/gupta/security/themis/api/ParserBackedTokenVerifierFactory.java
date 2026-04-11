package de.gupta.security.themis.api;

import de.gupta.security.themis.application.service.TokenVerificationServiceFactory;
import io.jsonwebtoken.JwtParser;

final class ParserBackedTokenVerifierFactory
{
	static TokenVerifier create(final TokenVerificationConfiguration configuration, final JwtParser parser)
	{
		return ConfiguredTokenVerifier.create(configuration, TokenVerificationServiceFactory.create(parser));
	}

	private ParserBackedTokenVerifierFactory()
	{
	}
}
