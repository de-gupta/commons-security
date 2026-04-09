package de.gupta.security.themis.application.service;

import de.gupta.security.themis.TestJwtTokens;
import de.gupta.security.themis.api.TokenClaimConfiguration;
import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.domain.model.*;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TokenVerificationServiceVerifyTokenTest
{
	private static final String EXPECTED_ISSUER = "https://issuer.example";
	private static final String EXPECTED_AUDIENCE = "themis-service";

	private TokenVerificationService service(final String parserSecret)
	{
		return TokenVerificationServiceFactory.create(
				Jwts.parser()
				    .verifyWith(Keys.hmacShaKeyFor(parserSecret.getBytes(StandardCharsets.UTF_8)))
				    .build());
	}

	private TokenVerificationPolicy defaultPolicy()
	{
		return TokenVerificationPolicy.of(Duration.ZERO, true);
	}

	private TokenClaimConfiguration defaultConfiguration()
	{
		return TokenClaimConfiguration.create().withRolesClaimName("user_roles");
	}

	private String signedToken(final TokenSpec spec)
	{
		final var builder = Jwts.builder()
		                        .expiration(Date.from(spec.expiration()))
		                        .claims(spec.claims())
		                        .signWith(Keys.hmacShaKeyFor(spec.secret().getBytes(StandardCharsets.UTF_8)));

		spec.subject().ifPresent(builder::subject);
		spec.notBefore().map(Date::from).ifPresent(builder::notBefore);
		spec.issuer().ifPresent(builder::issuer);
		if (!spec.audiences().isEmpty())
		{
			builder.audience().add(spec.audiences()).and();
		}

		return builder.compact();
	}

	private String unsecuredToken(final String subject)
	{
		return Jwts.builder()
		           .subject(subject)
		           .expiration(Date.from(Instant.now().plusSeconds(3600)))
		           .compact();
	}

	private record SuccessCase(String description, VerificationRequest request, String parserSecret,
	                           Consumer<NormalizedToken> assertion)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static SuccessCase of(final String description,
		                              final String token,
		                              final TokenVerificationPolicy policy,
		                              final TokenClaimConfiguration configuration,
		                              final String parserSecret,
		                              final Consumer<NormalizedToken> assertion)
		{
			return new SuccessCase(description,
					VerificationRequest.of(token,
							VerificationContext.of(VerificationKeyKind.HMAC, policy, configuration, Instant.now())),
					parserSecret,
					assertion);
		}
	}

	private record FailureCase(String description, VerificationRequest request, String parserSecret,
	                           VerificationFailureReason expectedReason)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static FailureCase of(final String description,
		                              final String token,
		                              final TokenVerificationPolicy policy,
		                              final TokenClaimConfiguration configuration,
		                              final String parserSecret,
		                              final VerificationFailureReason expectedReason)
		{
			return new FailureCase(description,
					VerificationRequest.of(token,
							VerificationContext.of(VerificationKeyKind.HMAC, policy, configuration, Instant.now())),
					parserSecret,
					expectedReason);
		}
	}

	private record TokenSpec(Optional<String> subject, Instant expiration, Optional<Instant> notBefore,
	                         Optional<String> issuer, Set<String> audiences, Map<String, ?> claims, String secret)
	{
		private static TokenSpec of(final String subject,
		                            final Instant expiration,
		                            final Optional<Instant> notBefore,
		                            final Optional<String> issuer,
		                            final Set<String> audiences,
		                            final Map<String, ?> claims,
		                            final String secret)
		{
			return new TokenSpec(Optional.ofNullable(subject), expiration, notBefore, issuer, audiences, claims,
					secret);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class SuccessCases
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("successCases")
		void shouldReturnVerificationSuccess(final SuccessCase testCase)
		{
			final VerificationResult result = service(testCase.parserSecret()).verifyToken(testCase.request());

			assertThat(result).isInstanceOf(VerificationSuccess.class);
			final NormalizedToken token = ((VerificationSuccess) result).token();
			testCase.assertion().accept(token);
		}

		private Stream<Arguments> successCases()
		{
			return Stream.of(
								 SuccessCase.of(
										 "minimal valid token",
										 TestJwtTokens.tokenWithRoles("user@example.com", Instant.now().plusSeconds(3600),
												 List.of("ROLE_USER")),
										 defaultPolicy(),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 token ->
										 {
											 assertThat(token.subject()).isEqualTo("user@example.com");
											 assertThat(token.roles()).containsExactly("ROLE_USER");
										 }),
								 SuccessCase.of(
										 "valid token with issuer and audience",
										 signedToken(TokenSpec.of(
												 "issuer-audience@example.com",
												 Instant.now().plusSeconds(3600),
												 Optional.empty(),
												 Optional.of(EXPECTED_ISSUER),
												 Set.of(EXPECTED_AUDIENCE),
												 Map.of("user_roles", List.of("ROLE_ADMIN")),
												 TestJwtTokens.SECRET)),
										 TokenVerificationPolicy.of(Duration.ZERO, true, Set.of(EXPECTED_AUDIENCE),
												 Optional.of(EXPECTED_ISSUER)),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 token ->
										 {
											 assertThat(token.subject()).isEqualTo("issuer-audience@example.com");
											 assertThat(token.issuer()).contains(EXPECTED_ISSUER);
											 assertThat(token.audiences()).containsExactly(EXPECTED_AUDIENCE);
										 }),
								 SuccessCase.of(
										 "valid token without subject requirement",
										 TestJwtTokens.tokenWithoutSubject(Instant.now().plusSeconds(3600)),
										 TokenVerificationPolicy.of(Duration.ZERO, false),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 token -> assertThat(token.subject()).isNull()))
			             .map(Arguments::of);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class TemporalFailures
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("temporalFailureCases")
		void shouldReturnFailureForTemporalValidation(final FailureCase testCase)
		{
			final VerificationResult result = service(testCase.parserSecret()).verifyToken(testCase.request());

			assertThat(result).isInstanceOf(VerificationFailure.class);
			assertThat(((VerificationFailure) result).reason()).isEqualTo(testCase.expectedReason());
		}

		private Stream<Arguments> temporalFailureCases()
		{
			return Stream.of(
								 FailureCase.of(
										 "expired token",
										 TestJwtTokens.tokenWithRoles("expired@example.com", Instant.now().minusSeconds(60),
												 List.of("ROLE_USER")),
										 defaultPolicy(),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.EXPIRED),
								 FailureCase.of(
										 "not yet valid token",
										 signedToken(TokenSpec.of(
												 "future@example.com",
												 Instant.now().plusSeconds(3600),
												 Optional.of(Instant.now().plusSeconds(300)),
												 Optional.empty(),
												 Set.of(),
												 Map.of("user_roles", List.of("ROLE_USER")),
												 TestJwtTokens.SECRET)),
										 defaultPolicy(),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.NOT_YET_VALID))
			             .map(Arguments::of);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class PolicyFailures
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("policyFailureCases")
		void shouldReturnFailureForPolicyValidation(final FailureCase testCase)
		{
			final VerificationResult result = service(testCase.parserSecret()).verifyToken(testCase.request());

			assertThat(result).isInstanceOf(VerificationFailure.class);
			assertThat(((VerificationFailure) result).reason()).isEqualTo(testCase.expectedReason());
		}

		private Stream<Arguments> policyFailureCases()
		{
			return Stream.of(
								 FailureCase.of(
										 "missing subject when subject required",
										 TestJwtTokens.tokenWithoutSubject(Instant.now().plusSeconds(3600)),
										 defaultPolicy(),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.MISSING_SUBJECT),
								 FailureCase.of(
										 "issuer mismatch",
										 signedToken(TokenSpec.of(
												 "issuer-mismatch@example.com",
												 Instant.now().plusSeconds(3600),
												 Optional.empty(),
												 Optional.of("https://another-issuer.example"),
												 Set.of(),
												 Map.of("user_roles", List.of("ROLE_USER")),
												 TestJwtTokens.SECRET)),
										 TokenVerificationPolicy.of(Duration.ZERO, true, Set.of(), Optional.of(EXPECTED_ISSUER)),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.INVALID_ISSUER),
								 FailureCase.of(
										 "audience mismatch",
										 signedToken(TokenSpec.of(
												 "audience-mismatch@example.com",
												 Instant.now().plusSeconds(3600),
												 Optional.empty(),
												 Optional.empty(),
												 Set.of("some-other-audience"),
												 Map.of("user_roles", List.of("ROLE_USER")),
												 TestJwtTokens.SECRET)),
										 TokenVerificationPolicy.of(Duration.ZERO, true, Set.of(EXPECTED_AUDIENCE),
												 Optional.empty()),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.INVALID_AUDIENCE))
			             .map(Arguments::of);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class SignatureAndStructureFailures
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("signatureAndStructureFailureCases")
		void shouldReturnFailureForSignatureAndStructureProblems(final FailureCase testCase)
		{
			final VerificationResult result = service(testCase.parserSecret()).verifyToken(testCase.request());

			assertThat(result).isInstanceOf(VerificationFailure.class);
			assertThat(((VerificationFailure) result).reason()).isEqualTo(testCase.expectedReason());
		}

		private Stream<Arguments> signatureAndStructureFailureCases()
		{
			return Stream.of(
								 FailureCase.of(
										 "wrong signature",
										 TestJwtTokens.tokenWithSecret("signature@example.com", Instant.now().plusSeconds(3600),
												 List.of("ROLE_USER"), "fedcba9876543210fedcba9876543210"),
										 defaultPolicy(),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.INVALID_SIGNATURE),
								 FailureCase.of(
										 "malformed token",
										 "not-a-jwt",
										 defaultPolicy(),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.MALFORMED),
								 FailureCase.of(
										 "unsupported unsecured token",
										 unsecuredToken("unsigned@example.com"),
										 defaultPolicy(),
										 defaultConfiguration(),
										 TestJwtTokens.SECRET,
										 VerificationFailureReason.UNSUPPORTED))
			             .map(Arguments::of);
		}
	}
}