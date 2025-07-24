package de.gupta.commons.security.token.jwt.filter;

import de.gupta.commons.security.token.jwt.service.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfiguration
{
	@Bean
	JwtFilter jwtFilter(final JwtService service)
	{
		return new JwtFilter(service);
	}
}