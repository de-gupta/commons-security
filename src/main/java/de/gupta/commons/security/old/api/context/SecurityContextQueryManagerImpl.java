package de.gupta.commons.security.old.api.context;

import de.gupta.commons.security.old.token.jwt.model.JwtPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

final class SecurityContextQueryManagerImpl implements SecurityContextQueryManager
{
	@Override
	public String username()
	{
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null)
		{
			throw new IllegalStateException("No authentication is available in the security context");
		}

		if (authentication.getPrincipal() instanceof JwtPrincipal principal)
		{
			return principal.username();
		}

		return authentication.getName();
	}

	@Override
	public boolean hasRole(final String role)
	{
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null)
		{
			return false;
		}

		return authentication.getAuthorities().stream()
		                     .map(GrantedAuthority::getAuthority).anyMatch(role::equalsIgnoreCase);
	}
}