package de.gupta.commons.security.token.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
final class JwtServiceImpl implements JwtService
{
	private final JwtParser jwtParser;

	@Override
	public boolean isTokenValid(final String token, final String username)
	{
		return username.equals(extractUsername(token)) && !isTokenExpired(token);
	}

	@Override
	public String extractUsername(final String token)
	{
		return jwtParser.parseSignedClaims(token).getPayload().getSubject();
	}

	private boolean isTokenExpired(final String token)
	{
		return extractExpiration(token).isBefore(Instant.now());
	}

	private Instant extractExpiration(final String token)
	{
		return jwtParser.parseSignedClaims(token).getPayload().getExpiration().toInstant();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Set<String> extractRoles(final String token)
	{
		List<String> roles = (List<String>) extractClaims(token).getPayload().get("user_roles", List.class);
		return new HashSet<>(roles);
	}

	private Jws<Claims> extractClaims(final String token)
	{
		return jwtParser.parseSignedClaims(token);
	}

	JwtServiceImpl(final JwtParser jwtParser)
	{
		this.jwtParser = jwtParser;
	}
}