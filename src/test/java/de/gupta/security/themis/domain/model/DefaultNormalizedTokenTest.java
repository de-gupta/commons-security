package de.gupta.security.themis.domain.model;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class DefaultNormalizedTokenTest
{
	@Test
	void shouldExposeAudiencesViaTokenUtility()
	{
		final DefaultNormalizedToken token = token(Map.of("aud", List.of(" service-a ", "service-b")));

		assertThat(token.audiences()).containsExactlyInAnyOrder("service-a", "service-b");
	}

	private DefaultNormalizedToken token(final Map<String, ?> claims)
	{
		return DefaultNormalizedToken.of("raw-token", Jwts.claims().add(new HashMap<>(claims)).build(), "user_roles");
	}

	private record TokenCase(String description, DefaultNormalizedToken token,
	                         Consumer<DefaultNormalizedToken> assertion)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static TokenCase of(final String description,
		                            final DefaultNormalizedToken token,
		                            final Consumer<DefaultNormalizedToken> assertion)
		{
			return new TokenCase(description, token, assertion);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class StandardFields
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("fieldCases")
		void shouldExposeStandardFields(final TokenCase testCase)
		{
			testCase.assertion().accept(testCase.token());
		}

		private Stream<Arguments> fieldCases()
		{
			final Instant issuedAt = Instant.parse("2026-04-07T10:15:30Z");
			final Instant expiresAt = Instant.parse("2026-04-07T11:15:30Z");
			final Instant notBefore = Instant.parse("2026-04-07T09:15:30Z");

			return Stream.of(
								 TokenCase.of(
										 "subject issuer and timestamps",
										 token(Map.of("iss", " issuer ", "sub", "user@example.com", "iat", Date.from(issuedAt),
												 "exp", Date.from(expiresAt))),
										 normalizedToken ->
										 {
											 assertThat(normalizedToken.rawToken()).isEqualTo("raw-token");
											 assertThat(normalizedToken.subject()).isEqualTo("user@example.com");
											 assertThat(normalizedToken.issuer()).contains("issuer");
											 assertThat(normalizedToken.issuedAt()).contains(issuedAt);
											 assertThat(normalizedToken.expiresAt()).contains(expiresAt);
										 }),
								 TokenCase.of(
										 "blank issuer is absent",
										 token(Map.of("iss", "   ")),
										 normalizedToken -> assertThat(normalizedToken.issuer()).isEmpty()),
								 TokenCase.of(
										 "missing timestamps are absent",
										 token(Map.of()),
										 normalizedToken ->
										 {
											 assertThat(normalizedToken.issuedAt()).isEmpty();
											 assertThat(normalizedToken.expiresAt()).isEmpty();
										 }),
								 TokenCase.of(
										 "notBefore is present when set",
										 token(Map.of("nbf", Date.from(notBefore))),
										 normalizedToken -> assertThat(normalizedToken.notBefore()).contains(notBefore)),
								 TokenCase.of(
										 "notBefore is absent when not set",
										 token(Map.of()),
										 normalizedToken -> assertThat(normalizedToken.notBefore()).isEmpty()),
								 TokenCase.of(
										 "notBefore before issuedAt is honoured",
										 token(Map.of("iat", Date.from(issuedAt), "nbf", Date.from(notBefore))),
										 normalizedToken ->
										 {
											 assertThat(normalizedToken.issuedAt()).contains(issuedAt);
											 assertThat(normalizedToken.notBefore()).contains(notBefore);
											 assertThat(normalizedToken.notBefore().get())
													 .isBefore(normalizedToken.issuedAt().get());
										 }))
			             .map(Arguments::of);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class Roles
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("rolesCases")
		void shouldExposeRoles(final TokenCase testCase)
		{
			testCase.assertion().accept(testCase.token());
		}

		private Stream<Arguments> rolesCases()
		{
			return Stream.of(
								 TokenCase.of(
										 "roles are returned trimmed",
										 token(Map.of("user_roles", List.of(" ROLE_USER ", "ROLE_ADMIN"))),
										 normalizedToken -> assertThat(normalizedToken.roles())
												 .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN")),
								 TokenCase.of(
										 "mixed collection filters non strings and blanks",
										 token(Map.of("user_roles", List.of(" ROLE_USER ", 7, "   ", "ROLE_ADMIN"))),
										 normalizedToken -> assertThat(normalizedToken.roles())
												 .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN")),
								 TokenCase.of(
										 "non collection claim becomes empty set",
										 token(Map.of("user_roles", "ROLE_USER")),
										 normalizedToken -> assertThat(normalizedToken.roles()).isEmpty()),
								 TokenCase.of(
										 "missing claim becomes empty set",
										 token(Map.of()),
										 normalizedToken -> assertThat(normalizedToken.roles()).isEmpty()),
								 TokenCase.of(
										 "custom claim name is used to read roles",
										 DefaultNormalizedToken.of("raw-token",
												 Jwts.claims().add(new HashMap<>(Map.of("authorities", List.of("ROLE_ADMIN"))))
									                 .build(),
												 "authorities"),
										 normalizedToken -> assertThat(normalizedToken.roles()).containsExactly("ROLE_ADMIN")))
			             .map(Arguments::of);
		}
	}

	@Deprecated
	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class StringClaims
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("stringClaimCases")
		void shouldNormalizeStringClaims(final TokenCase testCase)
		{
			testCase.assertion().accept(testCase.token());
		}

		private Stream<Arguments> stringClaimCases()
		{
			return Stream.of(
								 TokenCase.of(
										 "trimmed string claim is returned",
										 token(Map.of("department", " finance ")),
										 normalizedToken -> assertThat(normalizedToken.stringClaim("department")).contains(
												 "finance")),
								 TokenCase.of(
										 "blank string claim is absent",
										 token(Map.of("department", "   ")),
										 normalizedToken -> assertThat(normalizedToken.stringClaim("department")).isEmpty()),
								 TokenCase.of(
										 "non string claim is absent",
										 token(Map.of("department", 42)),
										 normalizedToken -> assertThat(normalizedToken.stringClaim("department")).isEmpty()),
								 TokenCase.of(
										 "missing string claim is absent",
										 token(Map.of()),
										 normalizedToken -> assertThat(normalizedToken.stringClaim("department")).isEmpty()))
			             .map(Arguments::of);
		}
	}

	@Deprecated
	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class StringListClaims
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("stringListCases")
		void shouldNormalizeStringListClaims(final TokenCase testCase)
		{
			testCase.assertion().accept(testCase.token());
		}

		private Stream<Arguments> stringListCases()
		{
			return Stream.of(
								 TokenCase.of(
										 "string list claim keeps trimmed values",
										 token(Map.of("user_roles", List.of(" ROLE_USER ", "ROLE_ADMIN"))),
										 normalizedToken -> assertThat(normalizedToken.stringListClaim("user_roles"))
												 .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN")),
								 TokenCase.of(
										 "mixed collection filters non strings and blanks",
										 token(Map.of("user_roles", List.of(" ROLE_USER ", 7, "   ", "ROLE_ADMIN"))),
										 normalizedToken -> assertThat(normalizedToken.stringListClaim("user_roles"))
												 .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN")),
								 TokenCase.of(
										 "non collection becomes empty set",
										 token(Map.of("user_roles", "ROLE_USER")),
										 normalizedToken -> assertThat(normalizedToken.stringListClaim("user_roles")).isEmpty()),
								 TokenCase.of(
										 "missing collection becomes empty set",
										 token(Map.of()),
										 normalizedToken -> assertThat(normalizedToken.stringListClaim("user_roles")).isEmpty()))
			             .map(Arguments::of);
		}
	}

	@Deprecated
	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class LongClaims
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("longClaimCases")
		void shouldNormalizeLongClaims(final TokenCase testCase)
		{
			testCase.assertion().accept(testCase.token());
		}

		private Stream<Arguments> longClaimCases()
		{
			return Stream.of(
								 TokenCase.of(
										 "number claim is exposed as long",
										 token(Map.of("ver", 7)),
										 normalizedToken -> assertThat(normalizedToken.longClaim("ver")).contains(7L)),
								 TokenCase.of(
										 "non number claim is absent",
										 token(Map.of("ver", "7")),
										 normalizedToken -> assertThat(normalizedToken.longClaim("ver")).isEmpty()),
								 TokenCase.of(
										 "missing number claim is absent",
										 token(Map.of()),
										 normalizedToken -> assertThat(normalizedToken.longClaim("ver")).isEmpty()))
			             .map(Arguments::of);
		}
	}
}