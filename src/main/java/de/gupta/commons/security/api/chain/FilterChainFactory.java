package de.gupta.commons.security.api.chain;

import de.gupta.commons.security.token.jwt.filter.JwtFilter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public final class FilterChainFactory
{
	private static final String[] swaggerPaths =
			{"/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**", "/v3/api-docs.yaml",
					"/swagger-resources/**", "/webjars/**"};
	private static final String[] actuatorPaths = {"/actuator/**"};

	public static SecurityFilterChain exposeSwaggerPaths(HttpSecurity http) throws Exception
	{
		return exposePaths(http, swaggerPaths);
	}

	public static SecurityFilterChain exposePaths(HttpSecurity http, final String[] paths)
			throws Exception
	{
		return http.securityMatchers(matchers -> matchers.requestMatchers(paths))
				   .csrf(AbstractHttpConfigurer::disable)
				   .httpBasic(Customizer.withDefaults())
				   .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				   .build();
	}

	public static SecurityFilterChain secureActuatorPathsWithAuthorities(HttpSecurity http, String[] authorities,
																		 JwtFilter filter) throws Exception
	{
		return securePathsWithAuthorities(http, actuatorPaths, authorities, filter);
	}

	public static SecurityFilterChain securePathsWithAuthorities(HttpSecurity http,
																 final String[] paths,
																 final String[] authorities,
																 final JwtFilter filter)
			throws Exception
	{
		return http.securityMatchers(matchers -> matchers.requestMatchers(paths))
				   .csrf(AbstractHttpConfigurer::disable)
				   .httpBasic(Customizer.withDefaults())
				   .authorizeHttpRequests(auth -> auth.anyRequest().hasAnyAuthority(authorities))
				   .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
				   .build();
	}

	public static SecurityFilterChain exposeActuatorPaths(HttpSecurity http) throws Exception
	{
		return exposePaths(http, actuatorPaths);
	}

	public static SecurityFilterChain secureWithFilter(HttpSecurity http, final JwtFilter filter)
			throws Exception
	{
		return http.csrf(AbstractHttpConfigurer::disable)
				   .httpBasic(Customizer.withDefaults())
				   .authorizeHttpRequests(request -> request.anyRequest().authenticated())
				   .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
				   .build();
	}

	private FilterChainFactory()
	{
	}
}