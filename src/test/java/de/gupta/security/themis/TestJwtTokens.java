package de.gupta.security.themis;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

public final class TestJwtTokens
{
	public static final String SECRET = "0123456789abcdef0123456789abcdef";
	public static final KeyPair RSA_KEY_PAIR = createKeyPair("RSA", 2048);
	public static final KeyPair EC_KEY_PAIR = createKeyPair("EC", 256);

	public static String tokenWithRoles(final String subject, final Instant expiration, final Collection<String> roles)
	{
		return token(subject, expiration, Map.of("user_roles", roles), SECRET);
	}

	public static RSAPublicKey rsaPublicKey()
	{
		return (RSAPublicKey) RSA_KEY_PAIR.getPublic();
	}

	public static ECPublicKey ecPublicKey()
	{
		return (ECPublicKey) EC_KEY_PAIR.getPublic();
	}

	public static String rsaTokenWithRoles(final String subject,
	                                       final Instant expiration,
	                                       final Collection<String> roles)
	{
		return token(subject, expiration, Map.of("user_roles", roles), RSA_KEY_PAIR);
	}

	public static String ecTokenWithRoles(final String subject,
	                                      final Instant expiration,
	                                      final Collection<String> roles)
	{
		return token(subject, expiration, Map.of("user_roles", roles), EC_KEY_PAIR);
	}

	public static String tokenWithRolesClaim(final String subject,
	                                         final Instant expiration,
	                                         final String claimName,
	                                         final Collection<String> roles)
	{
		return token(subject, expiration, Map.of(claimName, roles), SECRET);
	}

	public static String tokenWithoutRoles(final String subject, final Instant expiration)
	{
		return token(subject, expiration, Map.of(), SECRET);
	}

	public static String tokenWithoutSubject(final Instant expiration)
	{
		return Jwts.builder()
		           .expiration(Date.from(expiration))
		           .signWith(signingKey(SECRET))
		           .compact();
	}

	public static String tokenWithSecret(final String subject,
	                                     final Instant expiration,
	                                     final Collection<String> roles,
	                                     final String secret)
	{
		return token(subject, expiration, Map.of("user_roles", roles), secret);
	}

	private static String token(final String subject,
	                            final Instant expiration,
	                            final Map<String, ?> claims,
	                            final String secret)
	{
		return Jwts.builder()
		           .subject(subject)
		           .claims(claims)
		           .expiration(Date.from(expiration))
		           .signWith(signingKey(secret))
		           .compact();
	}

	private static String token(final String subject,
	                            final Instant expiration,
	                            final Map<String, ?> claims,
	                            final KeyPair keyPair)
	{
		return Jwts.builder()
		           .subject(subject)
		           .claims(claims)
		           .expiration(Date.from(expiration))
		           .signWith(keyPair.getPrivate())
		           .compact();
	}

	private static KeyPair createKeyPair(final String algorithm, final int keySize)
	{
		try
		{
			final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
			generator.initialize(keySize);
			return generator.generateKeyPair();
		}
		catch (final GeneralSecurityException ex)
		{
			throw new IllegalStateException("Could not generate test key pair for " + algorithm, ex);
		}
	}

	private static SecretKey signingKey(final String secret)
	{
		return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
	}

	private TestJwtTokens()
	{
	}
}