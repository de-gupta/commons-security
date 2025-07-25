package de.gupta.commons.security.token.jwt.service;

import java.util.Set;

public interface JwtService
{
	boolean isTokenValid(String token, String username);

	String extractUsername(String token);

	Set<String> extractRoles(String token);
}