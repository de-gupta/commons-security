package de.gupta.commons.security.old.api.configuration;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "security.jwt")
public record JwtConfigurationProperties(
		@NotBlank(message = "security.jwt.secret is required")
		@Size(min = 32, message = "security.jwt.secret must contain at least 32 characters")
		String secret,
		@NotBlank(message = "security.jwt.roles-claim must not be blank")
		@DefaultValue("user_roles")
		String rolesClaim)
{
}