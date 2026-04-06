package de.gupta.commons.security.api.chain;

import de.gupta.commons.security.TestJwtTokens;
import de.gupta.commons.security.ThemisConfiguration;
import de.gupta.commons.security.token.jwt.filter.JwtFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = DummyController.class)
@Import({FilterChainFactoryConsumerConfiguration.class, ThemisConfiguration.class})
@TestPropertySource(properties = "security.jwt.secret=" + TestJwtTokens.SECRET)
class ExposePathsSecurityFilterChainTest
{
	@Autowired
	private MockMvc mockMvc;

	@Test
	void shouldPermitConfiguredPublicPaths() throws Exception
	{
		mockMvc.perform(get("/public"))
		       .andExpect(status().isOk())
		       .andExpect(result -> assertThat(result.getResponse().getContentAsString())
					   .isEqualTo("Public access granted"));
	}

	@Test
	void shouldRejectUnsecuredPathWithoutToken() throws Exception
	{
		mockMvc.perform(get("/secure"))
		       .andExpect(status().isForbidden());
	}

	@Test
	void shouldAllowAuthorityRestrictedPathWithMatchingRole() throws Exception
	{
		final String token = TestJwtTokens.tokenWithRoles("admin", Instant.now().plusSeconds(3600),
				List.of("ROLE_ADMIN"));

		mockMvc.perform(get("/admin/config").header("Authorization", "Bearer " + token))
		       .andExpect(status().isOk())
		       .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains("Restricted"));
	}

	@Test
	void shouldRejectAuthorityRestrictedPathWithWrongRole() throws Exception
	{
		final String token = TestJwtTokens.tokenWithRoles("user", Instant.now().plusSeconds(3600),
				List.of("ROLE_USER"));

		mockMvc.perform(get("/admin/config").header("Authorization", "Bearer " + token))
		       .andExpect(status().isForbidden());
	}
}

@RestController
class DummyController
{
	@GetMapping("/public")
	public String publicEndpoint()
	{
		return "Public access granted";
	}

	@GetMapping("/secure")
	public String secureEndpoint()
	{
		return "Restricted";
	}

	@GetMapping("/admin/config")
	public String adminConfig()
	{
		return "Restricted";
	}
}

@Configuration
@EnableWebSecurity
class FilterChainFactoryConsumerConfiguration
{
	@Bean
	@Order(1)
	SecurityFilterChain exposeOnlyPublicPaths(final HttpSecurity http) throws Exception
	{
		return FilterChainFactory.exposePaths(http, new String[]{"/public/**"});
	}

	@Bean
	@Order(2)
	SecurityFilterChain secureAdminPaths(final HttpSecurity http, final JwtFilter jwtFilter) throws Exception
	{
		return FilterChainFactory.securePathsWithAuthorities(http, new String[]{"/admin/**"},
				new String[]{"ROLE_ADMIN"}, jwtFilter);
	}

	@Bean
	@Order(3)
	SecurityFilterChain securePaths(final HttpSecurity http, final JwtFilter filter) throws Exception
	{
		return FilterChainFactory.secureWithFilter(http, filter);
	}
}