package de.gupta.commons.security.token.jwt.filter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class TestSecurityConfiguration
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