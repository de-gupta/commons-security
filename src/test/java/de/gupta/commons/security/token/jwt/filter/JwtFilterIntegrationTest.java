package de.gupta.commons.security.token.jwt.filter;

import de.gupta.commons.security.TestJwtTokens;
import de.gupta.commons.security.ThemisConfiguration;
import de.gupta.commons.security.token.jwt.model.JwtPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = DummySecuredController.class)
@AutoConfigureMockMvc
@Import({ThemisConfiguration.class, JwtFilterTestSecurityConfiguration.class})
@TestPropertySource(properties = "security.jwt.secret=" + TestJwtTokens.SECRET)
class JwtFilterIntegrationTest
{
	@Autowired
	private MockMvc mockMvc;

	@BeforeEach
	void clearSecurityContext()
	{
		SecurityContextHolder.clearContext();
	}

	@Test
	void shouldAuthenticateAndExposeTypedPrincipalWhenTokenIsValid() throws Exception
	{
		final String token = TestJwtTokens.tokenWithRoles("user1", Instant.now().plusSeconds(3600),
				List.of("ROLE_USER", "ROLE_ADMIN"));

		mockMvc.perform(get("/secured-endpoint").header("Authorization", "Bearer " + token))
		       .andExpect(status().isOk())
		       .andExpect(result -> assertThat(result.getResponse().getContentAsString())
					   .contains("Access granted for user1"))
		       .andExpect(result -> assertThat(result.getResponse().getContentAsString())
					   .contains(JwtPrincipal.class.getSimpleName()))
		       .andExpect(result -> assertThat(result.getResponse().getContentAsString())
					   .contains("ROLE_USER"))
		       .andExpect(result -> assertThat(result.getResponse().getContentAsString())
					   .contains("ROLE_ADMIN"));
	}

	@Test
	void shouldLeaveRequestUnauthenticatedWhenTokenIsMissing() throws Exception
	{
		mockMvc.perform(get("/secured-endpoint"))
		       .andExpect(status().isForbidden());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	void shouldLeaveRequestUnauthenticatedWhenTokenIsMalformed() throws Exception
	{
		mockMvc.perform(get("/secured-endpoint").header("Authorization", "Bearer not-a-jwt"))
		       .andExpect(status().isForbidden());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	void shouldLeaveRequestUnauthenticatedWhenTokenIsExpired() throws Exception
	{
		final String token =
				TestJwtTokens.tokenWithRoles("user1", Instant.now().minusSeconds(60), List.of("ROLE_USER"));

		mockMvc.perform(get("/secured-endpoint").header("Authorization", "Bearer " + token))
		       .andExpect(status().isForbidden());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	void shouldLeaveRequestUnauthenticatedWhenSignatureIsInvalid() throws Exception
	{
		final String token = TestJwtTokens.tokenWithSecret("user1", Instant.now().plusSeconds(3600),
				List.of("ROLE_USER"), "fedcba9876543210fedcba9876543210");

		mockMvc.perform(get("/secured-endpoint").header("Authorization", "Bearer " + token))
		       .andExpect(status().isForbidden());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	void shouldPreserveExistingAuthentication() throws Exception
	{
		final var preAuth = new UsernamePasswordAuthenticationToken("existingUser", "pwd", List.of());
		final String token =
				TestJwtTokens.tokenWithRoles("ignored", Instant.now().plusSeconds(3600), List.of("ROLE_USER"));

		mockMvc.perform(get("/secured-endpoint")
					   .with(authentication(preAuth))
				       .header("Authorization", "Bearer " + token))
		       .andExpect(status().isOk())
		       .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains("existingUser"));
	}

	@Test
	void shouldIgnoreEmptyBearerToken() throws Exception
	{
		mockMvc.perform(get("/secured-endpoint").header("Authorization", "Bearer "))
		       .andExpect(status().isForbidden());
	}
}

@RestController
final class DummySecuredController
{
	@GetMapping("/secured-endpoint")
	public String securedEndpoint(final Authentication authentication)
	{
		if (authentication == null || !authentication.isAuthenticated())
		{
			return "Unauthenticated";
		}

		final String principalType = authentication.getPrincipal().getClass().getSimpleName();
		return "Access granted for " + authentication.getName()
				+ " with authorities " + authentication.getAuthorities()
				+ " using principal " + principalType;
	}
}

@Configuration
@EnableWebSecurity
class JwtFilterTestSecurityConfiguration
{
	@Bean
	SecurityFilterChain securityFilterChain(final HttpSecurity http, final JwtFilter jwtFilter) throws Exception
	{
		return http
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}
}