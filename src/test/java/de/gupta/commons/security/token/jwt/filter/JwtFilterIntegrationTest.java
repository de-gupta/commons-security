package de.gupta.commons.security.token.jwt.filter;

import de.gupta.commons.security.token.jwt.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = JwtFilterIntegrationTest.DummySecuredController.class)
@AutoConfigureMockMvc
@Import({JwtFilter.class})
class JwtFilterIntegrationTest
{
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private JwtService jwtService; // mock the service, not the filter

	@BeforeEach
	void clearSecurityContext()
	{
		SecurityContextHolder.clearContext();
	}

	@Test
	@DisplayName("Should authenticate and set SecurityContext when token is valid")
	void shouldAuthenticateWhenTokenIsValid() throws Exception
	{
		// Arrange
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

		// Act & Assert
		mockMvc.perform(get("/secured-endpoint")
					   .header("Authorization", "Bearer " + token))
			   .andExpect(status().isOk());

		assertThat(SecurityContextHolder.getContext().getAuthentication())
				.as("Security context should be populated")
				.isNotNull()
				.satisfies(auth ->
				{
					assertThat(auth.getName()).as("Authenticated username").isEqualTo("user1");
					assertThat(auth.getAuthorities().stream().map(GrantedAuthority.class::cast))
							.as("Granted authorities from token")
							.containsExactlyInAnyOrderElementsOf(authorities);
				});
	}

	@Test
	@DisplayName("Should not set SecurityContext when token is missing")
	void shouldSkipWhenNoTokenPresent() throws Exception
	{
		mockMvc.perform(get("/secured-endpoint"))
			   .andExpect(status().isForbidden()); // assuming your controller is secured

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
		SecurityContextHolder.getContext().setAuthentication(preAuth);

		mockMvc.perform(get("/secured-endpoint")
					   .header("Authorization", "Bearer any.token"))
			   .andExpect(status().isOk());

		assertThat(SecurityContextHolder.getContext().getAuthentication())
				.as("Should preserve existing authentication")
				.isSameAs(preAuth);
	}

	@RestController
	@RequestMapping
	static class DummySecuredController
	{
		@GetMapping("/secured-endpoint")
		public ResponseEntity<String> securedEndpoint(Authentication auth)
		{
			if (auth == null || !auth.isAuthenticated())
			{
				return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
			}
			return ResponseEntity.ok("Access granted for " + auth.getName());
		}
	}
}