package de.gupta.commons.security.old;

import de.gupta.commons.security.old.api.configuration.JwtConfigurationProperties;
import de.gupta.commons.security.old.api.context.SecurityContextQueryManager;
import de.gupta.commons.security.old.api.context.SecurityContextQueryManagerFactory;
import de.gupta.commons.security.old.token.jwt.filter.JwtFilter;
import de.gupta.commons.security.old.token.jwt.filter.JwtFilterFactory;
import de.gupta.commons.security.old.token.jwt.service.JwtService;
import de.gupta.commons.security.old.token.jwt.service.JwtServices;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.charset.StandardCharsets;

@Configuration
@EnableConfigurationProperties(JwtConfigurationProperties.class)
public class ThemisConfiguration
{
	@Bean
	JwtParser jwtParser(final JwtConfigurationProperties properties)
	{
		final var secretKey = Keys.hmacShaKeyFor(properties.secret().getBytes(StandardCharsets.UTF_8));
		return Jwts.parser().verifyWith(secretKey).build();
	}

	@Bean
	JwtService jwtService(final JwtParser jwtParser, final JwtConfigurationProperties properties)
	{
		return JwtServices.create(jwtParser, properties.rolesClaim());
	}

	@Bean
	JwtFilter jwtFilter(final JwtService jwtService)
	{
		return JwtFilterFactory.create(jwtService);
	}

	@Bean
	SecurityContextQueryManager securityContextQueryManager()
	{
		return SecurityContextQueryManagerFactory.create();
	}
}