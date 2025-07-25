package de.gupta.commons.security.api.context;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
final class SecurityContextQueryManagerImpl implements SecurityContextQueryManager
{
	@Override
	public String username()
	{
		return SecurityContextHolder.getContext().getAuthentication().getName();
	}

	@Override
	public boolean hasRole(final String role)
	{
		return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
									.map(GrantedAuthority::getAuthority).anyMatch(role::equalsIgnoreCase);
	}
}