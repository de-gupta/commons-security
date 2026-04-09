package de.gupta.security.themis.api;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TokenVerificationPolicyTest
{
	@Test
	void shouldCopyAudienceSetOnConstruction()
	{
		final Set<String> input = new HashSet<>(Set.of("service-a"));

		final TokenVerificationPolicy policy = TokenVerificationPolicy.of(Duration.ZERO, true, input, Optional.empty());
		input.add("service-b");

		assertThat(policy.expectedAudiences()).containsExactly("service-a");
	}

	@Test
	void shouldOverrideRolesClaimName()
	{
		final TokenVerificationPolicy policy = TokenVerificationPolicy.create()
		                                                              .withRolesClaimName("user_roles");

		assertThat(policy.rolesClaimName()).isEqualTo("user_roles");
	}

	private interface PolicyFactory
	{
		TokenVerificationPolicy create();
	}

	private record PolicyCase(String description, PolicyFactory factory, Duration clockSkew, boolean requireSubject,
	                          Set<String> expectedAudiences, Optional<String> expectedIssuer, String rolesClaimName)
	{
		@Override
		public String toString()
		{
			return description;
		}

		private static PolicyCase of(final String description,
		                             final PolicyFactory factory,
		                             final Duration clockSkew,
		                             final boolean requireSubject,
		                             final Set<String> expectedAudiences,
		                             final Optional<String> expectedIssuer)
		{
			return new PolicyCase(description, factory, clockSkew, requireSubject, expectedAudiences, expectedIssuer,
					TokenVerificationPolicy.DEFAULT_ROLES_CLAIM_NAME);
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class FactoryMethods
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("factoryCases")
		void shouldCreateExpectedPolicy(final PolicyCase testCase)
		{
			final TokenVerificationPolicy policy = testCase.factory().create();

			assertThat(policy.clockSkew()).isEqualTo(testCase.clockSkew());
			assertThat(policy.requireSubject()).isEqualTo(testCase.requireSubject());
			assertThat(policy.expectedAudiences()).isEqualTo(testCase.expectedAudiences());
			assertThat(policy.expectedIssuer()).isEqualTo(testCase.expectedIssuer());
			assertThat(policy.rolesClaimName()).isEqualTo(testCase.rolesClaimName());
		}

		private Stream<Arguments> factoryCases()
		{
			return Stream.of(
								 PolicyCase.of("create defaults", TokenVerificationPolicy::create, Duration.ZERO, false, Set.of(),
										 Optional.empty()),
								 PolicyCase.of("of duration", () -> TokenVerificationPolicy.of(Duration.ofSeconds(15)),
										 Duration.ofSeconds(15), false, Set.of(), Optional.empty()),
								 PolicyCase.of("of duration and subject",
										 () -> TokenVerificationPolicy.of(Duration.ofSeconds(30), true),
										 Duration.ofSeconds(30), true, Set.of(), Optional.empty()),
								 PolicyCase.of("of duration subject and audience",
										 () -> TokenVerificationPolicy.of(Duration.ofSeconds(45), true, Set.of("service-a")),
										 Duration.ofSeconds(45), true, Set.of("service-a"), Optional.empty()),
								 PolicyCase.of("full factory",
										 () -> TokenVerificationPolicy.of(Duration.ofSeconds(60), true,
												 Set.of("service-a", "service-b"),
												 Optional.of("https://issuer.example")),
										 Duration.ofSeconds(60), true, Set.of("service-a", "service-b"),
										 Optional.of("https://issuer.example")))
			             .map(Arguments::of);
		}
	}
}