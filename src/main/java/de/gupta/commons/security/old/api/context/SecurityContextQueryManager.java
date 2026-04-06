package de.gupta.commons.security.old.api.context;

public interface SecurityContextQueryManager
{
	String username();

	boolean hasRole(String role);
}