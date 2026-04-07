package de.gupta.commons.security.application.service;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.domain.model.*;
import de.gupta.commons.security.utility.TokenUtility;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

final class TokenVerificationServiceImpl implements TokenVerificationService
{
	private final JwtParser jwtParser;

	static TokenVerificationService create(final JwtParser jwtParser)
	{
		Objects.requireNonNull(jwtParser, "jwtParser must not be null");
		return new TokenVerificationServiceImpl(jwtParser);
	}

	@Override
	public VerificationResult verifyToken(final VerificationRequest request)
	{
		try
		{
			final TokenVerificationPolicy policy = request.context().policy();
			final Jws<Claims> jws = jwtParser.parseSignedClaims(request.token());
			final Claims claims = jws.getPayload();
			return validateClaims(claims, policy)
					.<VerificationResult>map(Function.identity())
					.orElseGet(() -> VerificationSuccess.of(DefaultNormalizedToken.of(request.token(), claims)));
		}
		catch (final ExpiredJwtException ex)
		{
			return failure(VerificationFailureReason.EXPIRED);
		}
		catch (final PrematureJwtException ex)
		{
			return failure(VerificationFailureReason.NOT_YET_VALID);
		}
		catch (final SecurityException ex)
		{
			return failure(VerificationFailureReason.INVALID_SIGNATURE);
		}
		catch (final UnsupportedJwtException ex)
		{
			return failure(VerificationFailureReason.UNSUPPORTED);
		}
		catch (final MalformedJwtException | IllegalArgumentException ex)
		{
			return failure(VerificationFailureReason.MALFORMED);
		}
		catch (final JwtException ex)
		{
			return failure(VerificationFailureReason.MALFORMED);
		}
	}

	private Optional<VerificationFailure> validateClaims(final Claims claims, final TokenVerificationPolicy policy)
	{
		return Stream.of(
							 validateSubject(claims, policy),
							 validateIssuer(claims, policy),
							 validateAudience(claims, policy))
		             .flatMap(Optional::stream)
		             .findFirst();
	}

	private Optional<VerificationFailure> validateSubject(final Claims claims, final TokenVerificationPolicy policy)
	{
		return policy.requireSubject() && StringSanitizationUtility.isAbsentOrBlank(claims.getSubject())
				? Optional.of(failure(VerificationFailureReason.MISSING_SUBJECT))
				: Optional.empty();
	}

	private Optional<VerificationFailure> validateIssuer(final Claims claims, final TokenVerificationPolicy policy)
	{
		return policy.expectedIssuer()
		             .filter(expectedIssuer -> !expectedIssuer.equals(claims.getIssuer()))
		             .map(_ -> failure(VerificationFailureReason.INVALID_ISSUER));
	}

	private Optional<VerificationFailure> validateAudience(final Claims claims, final TokenVerificationPolicy policy)
	{
		if (policy.expectedAudiences().isEmpty())
		{
			return Optional.empty();
		}

		final Set<String> actualAudiences = TokenUtility.audiencesOf(claims);
		return actualAudiences.containsAll(policy.expectedAudiences())
				? Optional.empty()
				: Optional.of(failure(VerificationFailureReason.INVALID_AUDIENCE));
	}

	private VerificationFailure failure(final VerificationFailureReason reason)
	{
		return VerificationFailure.of(reason);
	}

	private TokenVerificationServiceImpl(final JwtParser jwtParser)
	{
		this.jwtParser = jwtParser;
	}
}