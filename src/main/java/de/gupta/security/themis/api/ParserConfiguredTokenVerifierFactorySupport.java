package de.gupta.security.themis.api;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;

import java.time.Clock;
import java.util.Date;
import java.util.function.UnaryOperator;

final class ParserConfiguredTokenVerifierFactorySupport
{
	static TokenVerifier create(final TokenVerificationConfiguration configuration,
	                            final Clock clock,
	                            final UnaryOperator<JwtParserBuilder> signatureConfigurer)
	{
		final JwtParser parser = signatureConfigurer.apply(Jwts.parser())
		                                            .clock(() -> Date.from(clock.instant()))
		                                            .clockSkewSeconds(configuration.policy().clockSkew().toSeconds())
		                                            .build();

		return ParserBackedTokenVerifierFactory.create(configuration, parser);
	}

	private ParserConfiguredTokenVerifierFactorySupport()
	{
	}
}