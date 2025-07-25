package de.gupta.commons.security.api.chain;

import de.gupta.commons.security.token.jwt.filter.JwtFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public final class FilterChainFactory
{
	public static SecurityFilterChain securePathsWithAuthoritySecurityFilterChain(HttpSecurity http,
																				  final String[] paths,
																				  final String[] authorities,
																				  final JwtFilter filter)
			throws Exception
	{
		return SecurityConfigurerUtility.setUnauthenticatedBehaviour(http)
										.securityMatchers(matchers -> matchers.requestMatchers(paths))
										.csrf(AbstractHttpConfigurer::disable)
										.authorizeHttpRequests(auth -> auth.anyRequest().hasAnyAuthority(authorities))
										.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
										.build();
	}

	public static SecurityFilterChain exposePathsSecurityFilterChain(HttpSecurity http, final String[] paths)
			throws Exception
	{
		return SecurityConfigurerUtility.setUnauthenticatedBehaviour(http)
										.securityMatchers(matchers -> matchers.requestMatchers(paths))
										.csrf(AbstractHttpConfigurer::disable)
										.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
										.build();
	}

	public static SecurityFilterChain tokenAuthenticatedSecurityFilterChain(HttpSecurity http, final JwtFilter filter)
			throws Exception
	{
		return SecurityConfigurerUtility.setUnauthenticatedBehaviour(http)
										.csrf(AbstractHttpConfigurer::disable)
										.authorizeHttpRequests(request -> request.anyRequest().authenticated())
										.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
										.build();
	}

	private FilterChainFactory()
	{
	}
}

final class SecurityConfigurerUtility
{
	static HttpSecurity setUnauthenticatedBehaviour(HttpSecurity http) throws Exception
	{
		return http.exceptionHandling(ex -> ex
						   .authenticationEntryPoint((_, response, _) ->
						   {
							   response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							   response.getWriter().write("Unauthorized");
						   })
						   .accessDeniedHandler((_, response, _) ->
						   {
							   response.setStatus(HttpServletResponse.SC_FORBIDDEN);
							   response.getWriter().write("Forbidden");
						   }))
				   .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
	}

	private SecurityConfigurerUtility()
	{
	}
}