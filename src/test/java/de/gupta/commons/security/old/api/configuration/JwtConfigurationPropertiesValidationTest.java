package de.gupta.commons.security.old.api.configuration;

import de.gupta.commons.security.TestJwtTokens;
import de.gupta.commons.security.old.ThemisConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

class JwtConfigurationPropertiesValidationTest
{
	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withUserConfiguration(ImportedSecurityLibraryConfiguration.class);

	@Test
	void shouldFailStartupWhenSecretIsMissing()
	{
		contextRunner.run(context ->
		{
			assertThat(context).hasFailed();
			assertThat(context.getStartupFailure()).hasMessageContaining("JwtConfigurationProperties");
		});
	}

	@Test
	void shouldFailStartupWhenSecretIsBlank()
	{
		contextRunner
				.withPropertyValues("security.jwt.secret= ")
				.run(context ->
				{
					assertThat(context).hasFailed();
					assertThat(context.getStartupFailure()).hasMessageContaining("JwtConfigurationProperties");
				});
	}

	@Test
	void shouldBindCustomRolesClaim()
	{
		contextRunner
				.withPropertyValues(
						"security.jwt.secret=" + TestJwtTokens.SECRET,
						"security.jwt.roles-claim=realm_roles")
				.run(context ->
				{
					assertThat(context).hasNotFailed();
					assertThat(context.getBean(JwtConfigurationProperties.class).rolesClaim()).isEqualTo("realm_roles");
				});
	}
}

@Configuration
@Import(ThemisConfiguration.class)
class ImportedSecurityLibraryConfiguration
{
}