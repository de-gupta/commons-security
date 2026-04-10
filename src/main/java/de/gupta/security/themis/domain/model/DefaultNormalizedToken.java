package de.gupta.security.themis.domain.model;

import de.gupta.aletheia.collection.cascade.Cascade;
import de.gupta.aletheia.functional.Unfolding;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.security.themis.utility.TokenUtility;
import io.jsonwebtoken.Claims;

import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

record DefaultNormalizedToken(String rawToken, Claims claims, String rolesClaimName,
                              String versionClaimName) implements NormalizedToken
{
	static DefaultNormalizedToken of(final String rawToken, final Claims claims, final String rolesClaimName,
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
		                .infuse(Set.of());
	}

	@Override
	public Optional<String> issuer()
	{
		return Unfolding.beckon(claims.getIssuer())
		                .metamorphose(String::trim)
		                .discern(StringSanitizationUtility::isNotBlank)
		                .optional();
	}

	@Override
	public Set<String> audiences()
	{
		return TokenUtility.audiencesOf(claims);
	}

	@Override
	public Optional<Number> version()
	{
		return Optional.ofNullable(claims.get(versionClaimName))
		               .filter(Number.class::isInstance)
		               .map(Number.class::cast);
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
	public Optional<String> property(final String name)
	{
		return Unfolding.beckon(claims.get(name))
		                .discern(String.class::isInstance)
		                .metamorphose(String.class::cast)
		                .metamorphose(String::trim)
		                .discern(StringSanitizationUtility::isNotBlank)
		                .optional();
	}

	private Set<String> extractRoles(final Collection<?> values)
	{
		return Cascade.beckon(values)
		              .discern(String.class::isInstance)
		              .metamorphose(String.class::cast)
		              .metamorphose(String::trim)
		              .discern(StringSanitizationUtility::isNotBlank)
		              .coronate(s -> s.collect(Collectors.toUnmodifiableSet()), Set::of);
	}
}