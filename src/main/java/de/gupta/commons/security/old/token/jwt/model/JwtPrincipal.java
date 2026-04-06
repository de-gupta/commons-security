package de.gupta.commons.security.old.token.jwt.model;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

public final class JwtPrincipal implements Principal
{
	private final String token;
	private final String subject;
	private final Set<String> authorities;

	public static JwtPrincipal of(final String token, final String subject, final Set<String> authorities)
	{
		final String validatedToken = Objects.requireNonNull(token, "token must not be null").trim();
		final String validatedSubject = Objects.requireNonNull(subject, "subject must not be null").trim();
		Objects.requireNonNull(authorities, "authorities must not be null");

		if (validatedToken.isEmpty())
		{
			throw new IllegalArgumentException("token must not be blank");
		}
		if (validatedSubject.isEmpty())
		{
			throw new IllegalArgumentException("subject must not be blank");
		}

		final Set<String> validatedAuthorities = authorities.stream()
		                                                    .filter(Objects::nonNull)
		                                                    .map(String::trim)
		                                                    .filter(authority -> !authority.isEmpty())
		                                                    .collect(LinkedHashSet::new, Set::add, Set::addAll);

		return new JwtPrincipal(validatedToken, validatedSubject, Set.copyOf(validatedAuthorities));
	}

	public String token()
	{
		return token;
	}

	public String subject()
	{
		return subject;
	}

	public Set<String> authorities()
	{
		return authorities;
	}

	public String username()
	{
		return subject;
	}

	@Override
	public String getName()
	{
		return subject;
	}

	private JwtPrincipal(final String token, final String subject, final Set<String> authorities)
	{
		this.token = token;
		this.subject = subject;
		this.authorities = authorities;
	}
}