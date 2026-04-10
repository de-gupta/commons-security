package de.gupta.security.themis.api;

import de.gupta.security.themis.TestJwtTokens;
import de.gupta.security.themis.domain.model.VerificationFailure;
import de.gupta.security.themis.domain.model.VerificationFailureReason;
import de.gupta.security.themis.domain.model.VerificationResult;
import de.gupta.security.themis.domain.model.VerificationSuccess;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

final class TokenVerifierFactoryTest
{
	private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-04-09T12:00:00Z"), ZoneOffset.UTC);

	@Test
	void shouldVerifyValidToken()
	{
		final TokenVerifier verifier = TokenVerifierFactory.hmac(
				TokenVerificationConfiguration.of(
						TokenVerificationPolicy.of(Duration.ZERO, true, Set.of(), Optional.empty()),
						"user_roles",
						TokenVerificationConfiguration.DEFAULT_VERSION_CLAIM_NAME),
				TestJwtTokens.SECRET,
				CLOCK);
		final String token = TestJwtTokens.tokenWithRoles("user@example.com", CLOCK.instant().plusSeconds(3600),
				List.of("ROLE_USER"));

		final VerificationResult result = verifier.verify(token);

		assertThat(result).isInstanceOf(VerificationSuccess.class);
		final VerificationSuccess success = (VerificationSuccess) result;
		assertThat(success.token().subject()).isEqualTo("user@example.com");
		assertThat(success.token().roles()).containsExactly("ROLE_USER");
	}

	@Test
	void shouldRejectTokenWithWrongSignature()
	{
		final TokenVerifier verifier = TokenVerifierFactory.hmac(
				TokenVerificationConfiguration.of(TokenVerificationPolicy.create()),
				TestJwtTokens.SECRET,
				CLOCK);
		final String token = TestJwtTokens.tokenWithSecret("user@example.com", CLOCK.instant().plusSeconds(3600),
				List.of("ROLE_USER"), "fedcba9876543210fedcba9876543210");

		final VerificationResult result = verifier.verify(token);

		assertThat(result).isInstanceOf(VerificationFailure.class);
		assertThat(((VerificationFailure) result).reason()).isEqualTo(VerificationFailureReason.INVALID_SIGNATURE);
	}

	@Test
	void shouldRejectMissingSubjectWhenRequired()
	{
		final TokenVerifier verifier = TokenVerifierFactory.hmac(
				TokenVerificationConfiguration.of(TokenVerificationPolicy.of(Duration.ZERO, true)),
				TestJwtTokens.SECRET,
				CLOCK);
		final String token = TestJwtTokens.tokenWithoutSubject(CLOCK.instant().plusSeconds(3600));

		final VerificationResult result = verifier.verify(token);

		assertThat(result).isInstanceOf(VerificationFailure.class);
		assertThat(((VerificationFailure) result).reason()).isEqualTo(VerificationFailureReason.MISSING_SUBJECT);
	}

	@Test
	void shouldVerifyValidRsaToken()
	{
		final TokenVerifier verifier = TokenVerifierFactory.rsa(
				TokenVerificationConfiguration.of(
						TokenVerificationPolicy.of(Duration.ZERO, true, Set.of(), Optional.empty()),
						"user_roles",
						TokenVerificationConfiguration.DEFAULT_VERSION_CLAIM_NAME),
				TestJwtTokens.rsaPublicKey(),
				CLOCK);
		final String token = TestJwtTokens.rsaTokenWithRoles("rsa-user@example.com", CLOCK.instant().plusSeconds(3600),
				List.of("ROLE_RSA"));

		final VerificationResult result = verifier.verify(token);

		assertThat(result).isInstanceOf(VerificationSuccess.class);
		final VerificationSuccess success = (VerificationSuccess) result;
		assertThat(success.token().subject()).isEqualTo("rsa-user@example.com");
		assertThat(success.token().roles()).containsExactly("ROLE_RSA");
	}

	@Test
	void shouldVerifyValidEcToken()
	{
		final TokenVerifier verifier = TokenVerifierFactory.ec(
				TokenVerificationConfiguration.of(
						TokenVerificationPolicy.of(Duration.ZERO, true, Set.of(), Optional.empty()),
						"user_roles",
						TokenVerificationConfiguration.DEFAULT_VERSION_CLAIM_NAME),
				TestJwtTokens.ecPublicKey(),
				CLOCK);
		final String token = TestJwtTokens.ecTokenWithRoles("ec-user@example.com", CLOCK.instant().plusSeconds(3600),
				List.of("ROLE_EC"));

		final VerificationResult result = verifier.verify(token);

		assertThat(result).isInstanceOf(VerificationSuccess.class);
		final VerificationSuccess success = (VerificationSuccess) result;
		assertThat(success.token().subject()).isEqualTo("ec-user@example.com");
		assertThat(success.token().roles()).containsExactly("ROLE_EC");
	}
}
