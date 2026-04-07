package de.gupta.security.themis.utility;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.*;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TokenUtilityTest
{
	private Claims validatedClaims(final Map<String, ?> claims)
	{
		return Jwts.claims().add(new HashMap<>(claims)).build();
	}

	private Claims rawClaims(final Map<String, ?> claims)
	{
		return new RawClaims(claims);
	}

	private record AudienceCase(String description, Claims claims, Set<String> expectedAudiences)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static AudienceCase of(final String description, final Claims claims,
		                               final Set<String> expectedAudiences)
		{
			return new AudienceCase(description, claims, expectedAudiences);
		}
	}

	private static final class RawClaims extends HashMap<String, Object> implements Claims
	{
		@Override
		public String getIssuer()
		{
			return (String) get(ISSUER);
		}

		@Override
		public String getSubject()
		{
			return (String) get(SUBJECT);
		}

		@Override
		@SuppressWarnings("unchecked")
		public Set<String> getAudience()
		{
			return (Set<String>) get(AUDIENCE);
		}

		@Override
		public Date getExpiration()
		{
			return (Date) get(EXPIRATION);
		}

		@Override
		public Date getNotBefore()
		{
			return (Date) get(NOT_BEFORE);
		}

		@Override
		public Date getIssuedAt()
		{
			return (Date) get(ISSUED_AT);
		}

		@Override
		public String getId()
		{
			return (String) get(ID);
		}

		@Override
		@SuppressWarnings("unchecked")
		public <T> T get(final String claimName, final Class<T> requiredType)
		{
			return (T) get(claimName);
		}

		private RawClaims(final Map<String, ?> claims)
		{
			super(claims);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class AudiencesOf
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("audienceCases")
		void shouldNormalizeAudienceClaim(final AudienceCase testCase)
		{
			assertThat(TokenUtility.audiencesOf(testCase.claims())).isEqualTo(testCase.expectedAudiences());
		}

		private Stream<Arguments> audienceCases()
		{
			return Stream.of(
								 AudienceCase.of("single string audience", validatedClaims(Map.of("aud", "service-a")),
										 Set.of("service-a")),
								 AudienceCase.of("blank string audience", validatedClaims(Map.of("aud", "   ")), Set.of()),
								 AudienceCase.of("string list audience",
										 validatedClaims(Map.of("aud", List.of(" service-a ", "service-b"))),
										 Set.of("service-a", "service-b")),
								 AudienceCase.of("mixed list audience",
										 rawClaims(Map.of("aud", List.of(" service-a ", 7, "   ", "service-b"))),
										 Set.of("service-a", "service-b")),
								 AudienceCase.of("unsupported audience type", rawClaims(Map.of("aud", 42)), Set.of()),
								 AudienceCase.of("missing audience", validatedClaims(Map.of()), Set.of()))
			             .map(Arguments::of);
		}
	}
}