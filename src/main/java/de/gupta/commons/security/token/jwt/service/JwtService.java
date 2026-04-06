package de.gupta.commons.security.token.jwt.service;

import de.gupta.commons.security.token.jwt.model.JwtPrincipal;

import java.util.Optional;

public interface JwtService
{
	Optional<JwtPrincipal> verify(String token);
}