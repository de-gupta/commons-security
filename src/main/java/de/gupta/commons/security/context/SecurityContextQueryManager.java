package de.gupta.commons.security.context;

public interface SecurityContextQueryManager
{
	String username();

	boolean hasRole(String role);
}