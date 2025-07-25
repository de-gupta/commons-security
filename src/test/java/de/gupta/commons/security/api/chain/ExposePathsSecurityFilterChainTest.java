package de.gupta.commons.security.api.chain;

import de.gupta.commons.security.token.jwt.filter.JwtFilter;
import de.gupta.commons.security.token.jwt.service.JwtService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = DummyController.class)
@Import(SecurityConfiguration.class)
class ExposePathsSecurityFilterChainTest
{
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private JwtService jwtService;

	@Nested
	@DisplayName("Public Endpoint Access")
	class PublicAccessTests
	{
		@ParameterizedTest(name = "{index}: {0}")
		@MethodSource("allowedPathScenarios")
		@DisplayName("Should allow public access to exposed paths")
		void shouldPermitAllExposedPaths(String description, String path) throws Exception
		{
			mockMvc.perform(get(path))
				   .andExpect(status().isOk())
				   .andExpect(result -> assertThat(result.getResponse().getContentAsString())
						   .as("Response body for permitted path: " + path)
						   .contains("Public access granted"));
		}

		private static Stream<Arguments> allowedPathScenarios()
		{
			return Stream.of(
					arguments("Root path", "/public"),
					arguments("Nested public path", "/public/nested")
			);
		}
	}

	@Nested
	@DisplayName("Secured Endpoint Access (No Token)")
	class SecureAccessWithoutTokenTests
	{
		@ParameterizedTest(name = "{index}: {0}")
		@MethodSource("restrictedPathScenarios")
		@DisplayName("Should forbid access to unexposed paths when no token is provided")
		void shouldRejectAccessToOtherPaths(String description, String path) throws Exception
		{
			mockMvc.perform(get(path))
				   .andExpect(status().isUnauthorized())
				   .andExpect(result -> assertThat(result.getResponse().getContentAsString())
						   .as("Response for restricted path: " + path)
						   .doesNotContain("Public access granted"));
		}

		private static Stream<Arguments> restrictedPathScenarios()
		{
			return Stream.of(
					arguments("Secured path", "/secure"),
					arguments("Admin-only path", "/admin/config")
			);
		}
	}

	@Nested
	@DisplayName("Secured Endpoint Access (With Authority)")
	class SecureAccessWithAuthorityTests
	{
		@Test
		@DisplayName("Should allow access to authority-restricted path when user has required authority")
		void shouldPermitAccessToSecuredPathWithProperAuthority() throws Exception
		{
			String token = "valid.token";
			String username = "admin";
			Set<String> roles = Set.of("ROLE_ADMIN");

			when(jwtService.extractUsername(token)).thenReturn(username);
			when(jwtService.isTokenValid(token, username)).thenReturn(true);
			when(jwtService.extractRoles(token)).thenReturn(roles);

			mockMvc.perform(get("/admin/config")
						   .header("Authorization", "Bearer " + token))
				   .andExpect(status().isOk())
				   .andExpect(result -> assertThat(result.getResponse().getContentAsString())
						   .as("Content for authorized admin path")
						   .contains("Restricted"));
		}

		@Test
		@DisplayName("Should forbid access to authority-restricted path when user lacks required authority")
		void shouldRejectAccessToSecuredPathWithWrongAuthority() throws Exception
		{
			String token = "user.token";
			String username = "user";
			Set<String> roles = Set.of("ROLE_USER"); // no ROLE_ADMIN

			when(jwtService.extractUsername(token)).thenReturn(username);
			when(jwtService.isTokenValid(token, username)).thenReturn(true);
			when(jwtService.extractRoles(token)).thenReturn(roles);

			mockMvc.perform(get("/admin/config")
						   .header("Authorization", "Bearer " + token))
				   .andExpect(status().isForbidden());
		}
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

	@GetMapping("/public/nested")
	public String nestedPublic()
	{
		return "Public access granted to nested";
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
class SecurityConfiguration
{
	@Bean
	@Order(1)
	public SecurityFilterChain exposeOnlyPublicPaths(HttpSecurity http) throws Exception
	{
		return FilterChainFactory.exposePaths(http, new String[]{"/public/**"});
	}

	@Bean
	@Order(2)
	public SecurityFilterChain secureAdminPaths(HttpSecurity http, final JwtFilter jwtFilter) throws Exception
	{
		return FilterChainFactory.securePathsWithAuthorities(http, new String[]{"/admin/**"},
				new String[]{"ROLE_ADMIN"}, jwtFilter);
	}

	@Bean
	@Order(3)
	public SecurityFilterChain securePaths(HttpSecurity http, final JwtFilter filter) throws Exception
	{
		return FilterChainFactory.secureWithFilter(http, filter);
	}
}