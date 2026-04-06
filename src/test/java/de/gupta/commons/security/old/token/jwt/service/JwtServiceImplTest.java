package de.gupta.commons.security.old.token.jwt.service;

import de.gupta.commons.security.TestJwtTokens;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceImplTest
{
	private JwtService jwtService;

	@BeforeEach
	void setUp()
	{
		final var parser = Jwts.parser()
		                       .verifyWith(Keys.hmacShaKeyFor(TestJwtTokens.SECRET.getBytes(StandardCharsets.UTF_8)))
		                       .build();
		jwtService = new JwtServiceImpl(parser, "user_roles");
	}

	@Test
	void shouldVerifyValidToken()
	{
		final String token = TestJwtTokens.tokenWithRoles("user@example.com", Instant.now().plusSeconds(3600),
				List.of("ROLE_USER", "ROLE_ADMIN"));

		final var principal = jwtService.verify(token);

		assertThat(principal).isPresent();
		assertThat(principal.orElseThrow().subject()).isEqualTo("user@example.com");
		assertThat(principal.orElseThrow().username()).isEqualTo("user@example.com");
		assertThat(principal.orElseThrow().authorities()).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
	}

	@Test
	void shouldRejectExpiredToken()
	{
		final String token = TestJwtTokens.tokenWithRoles("user@example.com", Instant.now().minusSeconds(60),
				List.of("ROLE_USER"));

		assertThat(jwtService.verify(token)).isEmpty();
	}

	@Test
	void shouldRejectMalformedToken()
	{
		assertThat(jwtService.verify("not-a-jwt")).isEmpty();
	}

	@Test
	void shouldRejectWrongSignature()
	{
		final String token = TestJwtTokens.tokenWithSecret("user@example.com", Instant.now().plusSeconds(3600),
				List.of("ROLE_USER"), "fedcba9876543210fedcba9876543210");

		assertThat(jwtService.verify(token)).isEmpty();
	}

	@Test
	void shouldRequireSubject()
	{
		final String token = TestJwtTokens.tokenWithoutSubject(Instant.now().plusSeconds(3600));

		assertThat(jwtService.verify(token)).isEmpty();
	}

	@Test
	void shouldReturnEmptyAuthoritiesWhenRolesClaimIsMissing()
	{
		final String token = TestJwtTokens.tokenWithoutRoles("user@example.com", Instant.now().plusSeconds(3600));

		final var principal = jwtService.verify(token);

		assertThat(principal).isPresent();
		assertThat(principal.orElseThrow().authorities()).isEmpty();
	}

	@Test
	void shouldSupportCustomRolesClaim()
	{
		final var parser = Jwts.parser()
		                       .verifyWith(Keys.hmacShaKeyFor(TestJwtTokens.SECRET.getBytes(StandardCharsets.UTF_8)))
		                       .build();
		final JwtService customClaimService = new JwtServiceImpl(parser, "realm_roles");
		final String token = TestJwtTokens.tokenWithRolesClaim("user@example.com", Instant.now().plusSeconds(3600),
				"realm_roles", List.of("ROLE_PLATFORM"));

		final var principal = customClaimService.verify(token);

		assertThat(principal).isPresent();
		assertThat(principal.orElseThrow().authorities()).containsExactly("ROLE_PLATFORM");
	}
}