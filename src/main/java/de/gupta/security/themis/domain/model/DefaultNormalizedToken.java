package de.gupta.security.themis.domain.model;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.security.themis.utility.TokenUtility;
import io.jsonwebtoken.Claims;

import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public record DefaultNormalizedToken(String rawToken, Claims claims, String rolesClaimName,
                                     String versionClaimName) implements NormalizedToken
{
	public static DefaultNormalizedToken of(final String rawToken, final Claims claims, final String rolesClaimName,
	                                        final String versionClaimName)
	{
		return new DefaultNormalizedToken(rawToken, claims, rolesClaimName, versionClaimName);
	}

	@Override
	public String subject()
	{
		return claims.getSubject();
	}

	@Override
	public Set<String> roles()
	{
		return Unfolding.beckon(claims.get(rolesClaimName))
		                .discern(Collection.class::isInstance)
		                .metamorphose(Collection.class::cast)
		                .metamorphose(this::extractRoles)
		                .ordain(Set.of());
	}

	@Override
	public Optional<String> issuer()
	{
		return Optional.ofNullable(claims.getIssuer()).map(String::trim).filter(value -> !value.isEmpty());
	}

	@Override
	public Set<String> audiences()
	{
		return TokenUtility.audiencesOf(claims);
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
	public Optional<Instant> notBefore()
	{
		return Optional.ofNullable(claims.getNotBefore()).map(Date::toInstant);
	}

	@Override
	public Optional<Number> version()
	{
		return Optional.ofNullable(claims.get(versionClaimName))
		               .filter(Number.class::isInstance)
		               .map(Number.class::cast);
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

	private Set<String> extractRoles(final Collection<?> values)
	{
		return values.stream()
		             .filter(String.class::isInstance)
		             .map(String.class::cast)
		             .map(String::trim)
		             .filter(value -> !value.isEmpty())
		             .collect(Collectors.toUnmodifiableSet());
	}
}