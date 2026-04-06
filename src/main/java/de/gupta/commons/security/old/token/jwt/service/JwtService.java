package de.gupta.commons.security.old.token.jwt.service;

import de.gupta.commons.security.old.token.jwt.model.JwtPrincipal;

import java.util.Optional;

public interface JwtService
{
	Optional<JwtPrincipal> verify(String token);
}