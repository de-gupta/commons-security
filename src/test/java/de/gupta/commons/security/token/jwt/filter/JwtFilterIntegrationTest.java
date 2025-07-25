package de.gupta.commons.security.token.jwt.filter;

import de.gupta.commons.security.token.jwt.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = DummySecuredController.class)
@AutoConfigureMockMvc
@Import({TestSecurityConfiguration.class})
class JwtFilterIntegrationTest
{
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private JwtService jwtService;

	@BeforeEach
	void clearSecurityContext()
	{
		SecurityContextHolder.clearContext();
	}

	@Test
	@DisplayName("Should authenticate and set SecurityContext when token is valid")
	void shouldAuthenticateWhenTokenIsValid() throws Exception
	{
		String token = "valid.token";
		String username = "user1";
		Set<String> roles = Set.of("ROLE_USER", "ROLE_ADMIN");
		var authorities = roles.stream()
							   .map(SimpleGrantedAuthority::new)
							   .map(GrantedAuthority.class::cast)
							   .collect(Collectors.toSet());

		when(jwtService.extractUsername(token)).thenReturn(username);
		when(jwtService.isTokenValid(token, username)).thenReturn(true);
		when(jwtService.extractRole(token)).thenReturn(roles);

		mockMvc.perform(get("/secured-endpoint")
					   .header("Authorization", "Bearer " + token))
			   .andExpect(status().isOk())
			   .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains(
					   "Access granted for " + username))
			   .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains(
					   authorities.toString()));
	}

	@Test
	@DisplayName("Should not set SecurityContext when token is missing")
	void shouldSkipWhenNoTokenPresent() throws Exception
	{
		mockMvc.perform(get("/secured-endpoint"))
			   .andExpect(status().isForbidden());

		assertThat(SecurityContextHolder.getContext().getAuthentication())
				.as("Security context should remain empty")
				.isNull();
	}

	@Test
	@DisplayName("Should not set SecurityContext when token is invalid")
	void shouldSkipWhenTokenIsInvalid() throws Exception
	{
		String token = "invalid.token";
		String username = "user1";

		when(jwtService.extractUsername(token)).thenReturn(username);
		when(jwtService.isTokenValid(token, username)).thenReturn(false);

		mockMvc.perform(get("/secured-endpoint")
					   .header("Authorization", "Bearer " + token))
			   .andExpect(status().isForbidden());

		assertThat(SecurityContextHolder.getContext().getAuthentication())
				.as("Security context should not be set for invalid token")
				.isNull();
	}

	@Test
	@DisplayName("Should skip setting SecurityContext if already authenticated")
	void shouldSkipIfAlreadyAuthenticated() throws Exception
	{
		var preAuth = new UsernamePasswordAuthenticationToken("existingUser", "pwd", List.of());

		when(jwtService.extractUsername("any.token")).thenReturn("someUser");

		mockMvc.perform(get("/secured-endpoint")
					   .with(authentication(preAuth))
					   .header("Authorization", "Bearer any.token"))
			   .andExpect(status().isOk())
			   .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains(
					   "existingUser"));
	}

	@Test
	@DisplayName("Should skip setting SecurityContext when Authorization header is malformed")
	void shouldSkipWhenAuthorizationHeaderIsMalformed() throws Exception
	{
		mockMvc.perform(get("/secured-endpoint")
					   .header("Authorization", "NotBearer token"))
			   .andExpect(status().isForbidden());
	}

	@Test
	@DisplayName("Should skip setting SecurityContext when token is empty after Bearer")
	void shouldSkipWhenTokenIsEmpty() throws Exception
	{
		mockMvc.perform(get("/secured-endpoint")
					   .header("Authorization", "Bearer "))
			   .andExpect(status().isForbidden());
	}

	@Test
	@DisplayName("Should authenticate but with empty authorities if roles are missing")
	void shouldAuthenticateWithEmptyAuthorities() throws Exception
	{
		String token = "valid.token";
		String username = "user1";

		when(jwtService.extractUsername(token)).thenReturn(username);
		when(jwtService.isTokenValid(token, username)).thenReturn(true);
		when(jwtService.extractRole(token)).thenReturn(Set.of()); // no roles

		mockMvc.perform(get("/secured-endpoint")
					   .header("Authorization", "Bearer " + token))
			   .andExpect(status().isOk())
			   .andExpect(result -> assertThat(result.getResponse().getContentAsString()).contains("Access granted"));
	}

	@Test
	@DisplayName("Filter should not break the chain when token is missing or invalid for non-secured endpoints")
	void shouldProceedRequestWhenTokenIsMissingOrInvalidButNotBreakChain() throws Exception
	{
		mockMvc.perform(get("/unsecured-endpoint"))
			   .andExpect(status().is4xxClientError());
	}
}

@RestController
final class DummySecuredController
{
	private static final Logger log = LoggerFactory.getLogger(DummySecuredController.class);

	@GetMapping("/secured-endpoint")
	public ResponseEntity<String> securedEndpoint(Authentication auth)
	{
		if (auth == null || !auth.isAuthenticated())
		{
			log.warn("Access denied for unauthenticated user");
			log.warn("Authentication: {}", auth);
			return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
		}
		return ResponseEntity.ok("Access granted for " + auth.getName() + " with authorities " + auth.getAuthorities());
	}
}

@Configuration
@EnableWebSecurity
class TestSecurityConfiguration
{
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception
	{
		return
				http.csrf(AbstractHttpConfigurer::disable)
					.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
					.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
					.build();
	}
}