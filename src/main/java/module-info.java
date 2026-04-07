module themis
{
	exports de.gupta.commons.security.api;
	exports de.gupta.commons.security.domain.model;

	requires jakarta.servlet;
	requires jakarta.validation;
	requires jjwt.api;
	requires spring.boot;
	requires spring.context;
	requires spring.security.config;
	requires spring.security.core;
	requires spring.security.web;
	requires spring.web;
}