package de.gupta.commons.security.old.token.jwt.filter;

import de.gupta.commons.security.old.token.jwt.model.JwtPrincipal;
import de.gupta.commons.security.old.token.jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.stream.Collectors;

final class JwtFilterImpl extends OncePerRequestFilter implements JwtFilter
{
	private final JwtService jwtService;

	@Override
	protected void doFilterInternal(final HttpServletRequest request,
	                                final HttpServletResponse response,
	                                final FilterChain filterChain)
			throws ServletException, IOException
	{
		extractToken(request)
				.filter(token -> !token.isBlank())
				.filter(_ -> isSecurityContextEmpty())
				.flatMap(jwtService::verify)
				.ifPresent(principal -> setSecurityContext(principal, request));

		filterChain.doFilter(request, response);
	}

	private Optional<String> extractToken(final HttpServletRequest request)
	{
		String authorizationHeader = request.getHeader("Authorization");
		String authorizationStart = "Bearer ";
		return Optional.ofNullable(authorizationHeader)
		               .filter(header -> header.startsWith(authorizationStart))
		               .map(header -> header.substring(authorizationStart.length()));
	}

	private boolean isSecurityContextEmpty()
	{
		return SecurityContextHolder.getContext().getAuthentication() == null;
	}

	private void setSecurityContext(final JwtPrincipal principal, final HttpServletRequest request)
	{
		final var authorities = principal.authorities().stream()
		                                 .map(SimpleGrantedAuthority::new)
		                                 .map(GrantedAuthority.class::cast)
		                                 .collect(Collectors.toSet());
		UsernamePasswordAuthenticationToken authToken =
				UsernamePasswordAuthenticationToken.authenticated(principal, principal.token(), authorities);

		authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(authToken);
	}

	JwtFilterImpl(final JwtService jwtService)
	{
		this.jwtService = jwtService;
	}
}