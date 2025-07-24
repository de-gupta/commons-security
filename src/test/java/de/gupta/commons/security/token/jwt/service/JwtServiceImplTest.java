package de.gupta.commons.security.token.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceImplTest
{
	@Mock
	private JwtParser jwtParser;
	@Mock
	private Jws<Claims> jws;
	@Mock
	private Claims claims;

	private JwtServiceImpl jwtService;

	@BeforeEach
	void setUp()
	{
		jwtService = new JwtServiceImpl(jwtParser);
		Mockito.lenient().when(jws.getPayload()).thenReturn(claims);
	}

	@Nested
	class TokenValidationTests
	{
		@Test
		void shouldReturnTrueForValidToken()
		{
			when(jwtParser.parseSignedClaims("valid.token")).thenReturn(jws);
			when(claims.getSubject()).thenReturn("user1");
			when(claims.getExpiration()).thenReturn(Date.from(Instant.now().plusSeconds(3600)));

			boolean result = jwtService.isTokenValid("valid.token", "user1");

			assertThat(result)
					.as("Token with same username and an expiration date in the future should be valid")
					.isTrue();
		}

		@Test
		void shouldReturnFalseForMismatchedUsername()
		{
			when(jwtParser.parseSignedClaims("mismatch.token")).thenReturn(jws);
			when(claims.getSubject()).thenReturn("anotherUser");

			boolean result = jwtService.isTokenValid("mismatch.token", "user3");

			assertThat(result)
					.as("A token with a different username should be invalid")
					.isFalse();
		}

		@Test
		void shouldReturnFalseForExpiredToken()
		{
			when(jwtParser.parseSignedClaims("expired.token")).thenReturn(jws);
			when(claims.getSubject()).thenReturn("user4");
			when(claims.getExpiration()).thenReturn(Date.from(Instant.now().minusSeconds(60)));

			boolean result = jwtService.isTokenValid("expired.token", "user4");

			assertThat(result)
					.as("A token with an expired expiration date should be invalid")
					.isFalse();
		}

		@Test
		void shouldReturnFalseForExpiredTokenWithMismatchedUsername()
		{
			when(jwtParser.parseSignedClaims("expired.token")).thenReturn(jws);
			when(claims.getSubject()).thenReturn("user5");
			Mockito.lenient().when(claims.getExpiration()).thenReturn(Date.from(Instant.now().minusSeconds(60)));

			boolean result = jwtService.isTokenValid("expired.token", "user6");

			assertThat(result)
					.as("A token with an expired expiration date and mismatched username should be invalid")
					.isFalse();
		}

		@Test
		void shouldThrowExceptionIfTokenParsingFails()
		{
			when(jwtParser.parseSignedClaims("bad.token")).thenThrow(new RuntimeException("Invalid token"));

			assertThatThrownBy(() -> jwtService.isTokenValid("bad.token", "userX"))
					.isInstanceOf(RuntimeException.class)
					.hasMessageContaining("Invalid token");
		}
	}

	@Nested
	class UsernameExtractionTests
	{
		@Test
		void shouldExtractUsername()
		{
			when(jwtParser.parseSignedClaims("token")).thenReturn(jws);
			when(claims.getSubject()).thenReturn("user@example.com");

			String result = jwtService.extractUsername("token");

			assertThat(result)
					.as("An email Username should be extracted from the token")
					.isEqualTo("user@example.com");
		}

		@Test
		void shouldExtractEmptyUsername()
		{
			when(jwtParser.parseSignedClaims("empty.token")).thenReturn(jws);
			when(claims.getSubject()).thenReturn("");

			String result = jwtService.extractUsername("empty.token");

			assertThat(result)
					.as("An empty Username should be extracted from the token")
					.isEmpty();
		}

		@Test
		void shouldThrowWhenUsernameExtractionFails()
		{
			when(jwtParser.parseSignedClaims("broken.token")).thenThrow(new RuntimeException("Parse error"));

			assertThatThrownBy(() -> jwtService.extractUsername("broken.token"))
					.isInstanceOf(RuntimeException.class)
					.hasMessageContaining("Parse error");
		}
	}

	@Nested
	class RoleExtractionTests
	{
		@Test
		void shouldExtractSingleRole()
		{
			when(jwtParser.parseSignedClaims("token")).thenReturn(jws);
			when(claims.get("user_roles", List.class)).thenReturn(List.of("ROLE_USER"));

			Set<String> result = jwtService.extractRole("token");

			assertThat(result)
					.as("A single role should be extracted from the token")
					.containsExactly("ROLE_USER");
		}

		@Test
		void shouldExtractMultipleRoles()
		{
			when(jwtParser.parseSignedClaims("token")).thenReturn(jws);
			when(claims.get("user_roles", List.class)).thenReturn(List.of("ROLE_USER", "ROLE_ADMIN"));

			Set<String> result = jwtService.extractRole("token");

			assertThat(result)
					.as("Multiple roles should be extracted from the token")
					.containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
		}

		@Test
		void shouldExtractNoRolesWhenEmptyList()
		{
			when(jwtParser.parseSignedClaims("token")).thenReturn(jws);
			when(claims.get("user_roles", List.class)).thenReturn(List.of());

			Set<String> result = jwtService.extractRole("token");

			assertThat(result)
					.as("An empty list of roles should be converted to an empty set")
					.isEmpty();
		}

		@Test
		void shouldDeduplicateRoles()
		{
			when(jwtParser.parseSignedClaims("token")).thenReturn(jws);
			when(claims.get("user_roles", List.class)).thenReturn(List.of("ROLE_USER", "ROLE_USER", "ROLE_ADMIN"));

			Set<String> result = jwtService.extractRole("token");

			assertThat(result)
					.as("Duplicate roles should be deduplicated")
					.containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
		}

		@Test
		void shouldThrowWhenTokenParsingFails()
		{
			when(jwtParser.parseSignedClaims("broken.token")).thenThrow(new RuntimeException("JWT parse failed"));

			assertThatThrownBy(() -> jwtService.extractRole("broken.token"))
					.isInstanceOf(RuntimeException.class)
					.hasMessageContaining("JWT parse failed");
		}

		@Test
		void shouldThrowWhenRoleClaimCastingFails()
		{
			when(jwtParser.parseSignedClaims("wrong.claim")).thenReturn(jws);
			when(claims.get("user_roles", List.class)).thenThrow(new ClassCastException("Wrong type"));

			assertThatThrownBy(() -> jwtService.extractRole("wrong.claim"))
					.isInstanceOf(ClassCastException.class)
					.hasMessageContaining("Wrong type");
		}
	}
}