package de.gupta.commons.security.token.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
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
	public Set<String> extractRole(final String token)
	{
		List<String> roles = (List<String>) extractClaims(token).getPayload().get("user_roles", List.class);
		return new HashSet<>(roles);
	}

	private Jws<Claims> extractClaims(final String token)
	{
		return jwtParser.parseSignedClaims(token);
	}

	JwtServiceImpl(@Value("${security.jwtSecret}") final String secret)
	{
		byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);

		final SecretKey secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
		jwtParser = Jwts.parser().verifyWith(secretKey).build();
	}
}