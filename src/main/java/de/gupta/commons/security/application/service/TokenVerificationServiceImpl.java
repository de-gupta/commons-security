package de.gupta.commons.security.application.service;

import de.gupta.commons.security.api.TokenVerificationPolicy;
import de.gupta.commons.security.domain.model.*;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

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

	private record DefaultNormalizedToken(String rawToken, Claims claims) implements NormalizedToken
	{
		static NormalizedToken of(final String rawToken, final Claims claims)
		{
			return new DefaultNormalizedToken(rawToken, claims);
		}

		static Set<String> audiencesOf(final Claims claims)
		{
			final Object rawAudience = claims.get("aud");
			if (rawAudience instanceof String audience)
			{
				return audience.isBlank() ? Set.of() : Set.of(audience);
			}
			if (rawAudience instanceof Collection<?> values)
			{
				return values.stream()
				             .filter(String.class::isInstance)
				             .map(String.class::cast)
				             .map(String::trim)
				             .filter(value -> !value.isEmpty())
				             .collect(Collectors.toUnmodifiableSet());
			}
			return Set.of();
		}


		@Override
		public String subject()
		{
			return claims.getSubject();
		}

		@Override
		public Optional<String> issuer()
		{
			return Optional.ofNullable(claims.getIssuer()).map(String::trim).filter(value -> !value.isEmpty());
		}

		@Override
		public Set<String> audiences()
		{
			return audiencesOf(claims);
		}

		@Override
		public Optional<Instant> issuedAt()
		{
			return Optional.ofNullable(claims.getIssuedAt()).map(Date::toInstant);
		}

		@Override
		public Optional<Instant> expiresAt()
		{
			return Optional.ofNullable(claims.getExpiration()).map(Date::toInstant);
		}

		@Override
		public Optional<String> stringClaim(final String name)
		{
			return Optional.ofNullable(claims.get(name))
			               .filter(String.class::isInstance)
			               .map(String.class::cast)
			               .map(String::trim)
			               .filter(value -> !value.isEmpty());
		}

		@Override
		public Set<String> stringListClaim(final String name)
		{
			final Object rawClaim = claims.get(name);
			if (!(rawClaim instanceof Collection<?> values))
			{
				return Set.of();
			}

			return values.stream()
			             .filter(String.class::isInstance)
			             .map(String.class::cast)
			             .map(String::trim)
			             .filter(value -> !value.isEmpty())
			             .collect(Collectors.toUnmodifiableSet());
		}

		@Override
		public Optional<Long> longClaim(final String name)
		{
			return Optional.ofNullable(claims.get(name))
			               .filter(Number.class::isInstance)
			               .map(Number.class::cast)
			               .map(Number::longValue);
		}

	}
}