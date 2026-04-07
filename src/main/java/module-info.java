module de.gupta.themis
{
	exports de.gupta.security.themis.api;
	exports de.gupta.security.themis.domain.model;

	requires jjwt.api;

	requires de.gupta.athena;
	requires de.gupta.aletheia;
}