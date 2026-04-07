package de.gupta.commons.security.application.service;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.domain.model.*;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;

import java.util.Objects;
import java.util.Set;

final class TokenVerificationServiceImpl implements TokenVerificationService
{
	private final JwtParser jwtParser;
	private final TokenVerificationPolicy policy;

	public static TokenVerificationService create(final JwtParser jwtParser, final TokenVerificationPolicy policy)
	{
		return new TokenVerificationServiceImpl(jwtParser, policy);
	}

	@Override
	public VerificationResult verifyToken(final VerificationRequest request)
	{
		try
		{
			final Jws<Claims> jws = jwtParser.parseSignedClaims(request.token());
			final Claims claims = jws.getPayload();

			final VerificationFailure failure = validateClaims(claims);
			if (failure != null)
			{
				return failure;
			}

			return new VerificationSuccess(DefaultNormalizedToken.of(request.token(), claims));
		}
		catch (final ExpiredJwtException ex)
		{
			return VerificationFailure.of(VerificationFailureReason.EXPIRED);
		}
		catch (final PrematureJwtException ex)
		{
			return VerificationFailure.of(VerificationFailureReason.NOT_YET_VALID);
		}
		catch (final SecurityException ex)
		{
			return VerificationFailure.of(VerificationFailureReason.INVALID_SIGNATURE);
		}
		catch (final UnsupportedJwtException ex)
		{
			return VerificationFailure.of(VerificationFailureReason.UNSUPPORTED);
		}
		catch (final MalformedJwtException | IllegalArgumentException ex)
		{
			return VerificationFailure.of(VerificationFailureReason.MALFORMED);
		}
		catch (final JwtException ex)
		{
			return VerificationFailure.of(VerificationFailureReason.MALFORMED);
		}
	}

	private VerificationFailure validateClaims(final Claims claims)
	{
		if (policy.requireSubject() && isBlank(claims.getSubject()))
		{
			return VerificationFailure.of(VerificationFailureReason.MISSING_SUBJECT);
		}

		if (policy.expectedIssuer().isPresent())
		{
			final String expectedIssuer = policy.expectedIssuer().orElseThrow();
			if (!expectedIssuer.equals(claims.getIssuer()))
			{
				return VerificationFailure.of(VerificationFailureReason.INVALID_ISSUER);
			}
		}

		if (!policy.expectedAudiences().isEmpty())
		{
			final Set<String> actualAudiences = DefaultNormalizedToken.audiencesOf(claims);
			if (!actualAudiences.containsAll(policy.expectedAudiences()))
			{
				return VerificationFailure.of(VerificationFailureReason.INVALID_AUDIENCE);
			}
		}

		return null;
	}

	private boolean isBlank(final String value)
	{
		return value == null || value.trim().isEmpty();
	}

	private TokenVerificationServiceImpl(final JwtParser jwtParser, final TokenVerificationPolicy policy)
	{
		this.jwtParser = Objects.requireNonNull(jwtParser, "jwtParser must not be null");
		this.policy = Objects.requireNonNull(policy, "policy must not be null");
	}
}