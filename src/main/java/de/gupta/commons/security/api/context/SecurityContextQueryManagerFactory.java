package de.gupta.commons.security.api.context;

public final class SecurityContextQueryManagerFactory
{
	public static SecurityContextQueryManager create()
	{
		return new SecurityContextQueryManagerImpl();
	}

	private SecurityContextQueryManagerFactory()
	{
	}
}