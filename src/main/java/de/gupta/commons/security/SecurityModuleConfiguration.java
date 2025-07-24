package de.gupta.commons.security;

import de.gupta.commons.security.configuration.SecurityConfigurationProperties;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
@ComponentScan
@EnableConfigurationProperties(SecurityConfigurationProperties.class)
public class SecurityModuleConfiguration
{
	@Bean
	JwtParser jwtParser(@Value("${security.jwtSecret}") final String secret)
	{
		byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);

		final SecretKey secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
		return Jwts.parser().verifyWith(secretKey).build();
	}
}