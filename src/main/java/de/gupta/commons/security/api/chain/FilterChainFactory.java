package de.gupta.commons.security.api.chain;

import de.gupta.commons.security.token.jwt.filter.JwtFilter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
		return http.securityMatchers(matchers -> matchers.requestMatchers(paths))
				   .csrf(AbstractHttpConfigurer::disable)
				   .httpBasic(Customizer.withDefaults())
				   .authorizeHttpRequests(auth -> auth.anyRequest().hasAnyAuthority(authorities))
				   .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
				   .build();
	}

	public static SecurityFilterChain exposePathsSecurityFilterChain(HttpSecurity http, final String[] paths)
			throws Exception
	{
		return http.securityMatchers(matchers -> matchers.requestMatchers(paths))
				   .csrf(AbstractHttpConfigurer::disable)
				   .httpBasic(Customizer.withDefaults())
				   .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				   .build();
	}

	public static SecurityFilterChain tokenAuthenticatedSecurityFilterChain(HttpSecurity http, final JwtFilter filter)
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