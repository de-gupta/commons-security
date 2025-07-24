package de.gupta.commons.security;

import de.gupta.commons.security.configuration.SecurityConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan
@EnableConfigurationProperties(SecurityConfigurationProperties.class)
public class SecurityModuleConfiguration
{
}