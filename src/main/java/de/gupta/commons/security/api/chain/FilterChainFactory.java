package de.gupta.commons.security.api.chain;

import jakarta.servlet.Filter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public final class FilterChainFactory
{
	public static SecurityFilterChain securePathsWithAuthoritySecurityFilterChain(HttpSecurity http,
																				  final String[] paths,
																				  final String[] authorities)
			throws Exception
	{
		return http.securityMatchers(matchers -> matchers.requestMatchers(paths))
				   .csrf(AbstractHttpConfigurer::disable)
				   .authorizeHttpRequests(auth -> auth.anyRequest().hasAnyAuthority(authorities))
				   .build();
	}

	public static SecurityFilterChain exposePathsSecurityFilterChain(HttpSecurity http, final String[] paths)
			throws Exception
	{
		return http.securityMatchers(matchers -> matchers.requestMatchers(paths))
				   .csrf(AbstractHttpConfigurer::disable)
				   .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				   .build();
	}

	public static SecurityFilterChain tokenAuthenticatedSecurityFilterChain(HttpSecurity http, final Filter filter)
			throws Exception
	{
		return http.csrf(AbstractHttpConfigurer::disable)
				   .authorizeHttpRequests(request -> request.anyRequest().authenticated())
				   .httpBasic(Customizer.withDefaults())
				   .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				   .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
				   .build();
	}

	private FilterChainFactory()
	{
	}
}