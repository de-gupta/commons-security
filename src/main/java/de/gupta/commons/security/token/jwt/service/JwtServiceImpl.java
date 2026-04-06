package de.gupta.commons.security.token.jwt.service;

import de.gupta.commons.security.token.jwt.model.JwtPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

final class JwtServiceImpl implements JwtService
{
	private final JwtParser jwtParser;
	private final String rolesClaim;

	@Override
	public Optional<JwtPrincipal> verify(final String token)
	{
		try
		{
			final Claims claims = extractClaims(token).getPayload();
			return extractSubject(claims)
					.map(subject -> JwtPrincipal.of(token, subject, extractRoles(claims)));
		}
		catch (final JwtException | IllegalArgumentException ex)
		{
			return Optional.empty();
		}
	}

	private Optional<String> extractSubject(final Claims claims)
	{
		return Optional.ofNullable(claims.getSubject())
		               .map(String::trim)
		               .filter(subject -> !subject.isEmpty());
	}

	private Set<String> extractRoles(final Claims claims)
	{
		final Object rawClaim = claims.get(rolesClaim);
		if (!(rawClaim instanceof Collection<?> values))
		{
			return Set.of();
		}

		return values.stream()
		             .filter(String.class::isInstance)
		             .map(String.class::cast)
		             .map(String::trim)
		             .filter(role -> !role.isEmpty())
		             .collect(LinkedHashSet::new, Set::add, Set::addAll);
	}

	private Jws<Claims> extractClaims(final String token)
	{
		return jwtParser.parseSignedClaims(token);
	}

	JwtServiceImpl(final JwtParser jwtParser, final String rolesClaim)
	{
		this.jwtParser = jwtParser;
		this.rolesClaim = rolesClaim;
	}
}