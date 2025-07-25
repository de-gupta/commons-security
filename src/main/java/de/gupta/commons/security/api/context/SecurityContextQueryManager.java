package de.gupta.commons.security.api.context;

public interface SecurityContextQueryManager
{
	String username();

	boolean hasRole(String role);
}