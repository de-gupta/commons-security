package de.gupta.security.themis.api;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
final class TokenClaimConfigurationTest
{
	@Test
	void shouldOverrideRolesClaimName()
	{
		final TokenClaimConfiguration config = TokenClaimConfiguration.create()
		                                                              .withRolesClaimName("user_roles");

		assertThat(config.rolesClaimName()).isEqualTo("user_roles");
	}

	@Test
	void shouldOverrideVersionClaimName()
	{
		final TokenClaimConfiguration config = TokenClaimConfiguration.create()
		                                                              .withVersionClaimName("revision");

		assertThat(config.versionClaimName()).isEqualTo("revision");
	}

	@Test
	void shouldPreserveOtherFieldWhenOverridingRolesClaimName()
	{
		final TokenClaimConfiguration config = TokenClaimConfiguration.create()
		                                                              .withVersionClaimName("revision")
		                                                              .withRolesClaimName("user_roles");

		assertThat(config.rolesClaimName()).isEqualTo("user_roles");
		assertThat(config.versionClaimName()).isEqualTo("revision");
	}

	@Test
	void shouldPreserveOtherFieldWhenOverridingVersionClaimName()
	{
		final TokenClaimConfiguration config = TokenClaimConfiguration.create()
		                                                              .withRolesClaimName("user_roles")
		                                                              .withVersionClaimName("revision");

		assertThat(config.rolesClaimName()).isEqualTo("user_roles");
		assertThat(config.versionClaimName()).isEqualTo("revision");
	}

	private record ConfigCase(String description, TokenClaimConfiguration configuration,
	                          String rolesClaimName, String versionClaimName)
	{
		@Override
		public String toString()
		{
			return description;
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	final class FactoryMethods
	{
		@ParameterizedTest(name = "{0}")
		@MethodSource("factoryCases")
		void shouldCreateExpectedConfiguration(final ConfigCase testCase)
		{
			assertThat(testCase.configuration().rolesClaimName()).isEqualTo(testCase.rolesClaimName());
			assertThat(testCase.configuration().versionClaimName()).isEqualTo(testCase.versionClaimName());
		}

		private Stream<Arguments> factoryCases()
		{
			return Stream.of(
					Arguments.of(new ConfigCase(
							"create defaults",
							TokenClaimConfiguration.create(),
							TokenClaimConfiguration.DEFAULT_ROLES_CLAIM_NAME,
							TokenClaimConfiguration.DEFAULT_VERSION_CLAIM_NAME)),
					Arguments.of(new ConfigCase(
							"custom roles claim name",
							TokenClaimConfiguration.create().withRolesClaimName("user_roles"),
							"user_roles",
							TokenClaimConfiguration.DEFAULT_VERSION_CLAIM_NAME)),
					Arguments.of(new ConfigCase(
							"custom version claim name",
							TokenClaimConfiguration.create().withVersionClaimName("revision"),
							TokenClaimConfiguration.DEFAULT_ROLES_CLAIM_NAME,
							"revision")));
		}
	}
}