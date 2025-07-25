package de.gupta.commons.security.token.jwt.filter;

import de.gupta.commons.security.token.jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
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
				.map(token -> Map.entry(token, jwtService.extractUsername(token)))
				.filter(e -> jwtService.isTokenValid(e.getKey(), e.getValue()))
				.map(e ->
						{
							final var authorities = jwtService.extractRoles(e.getKey())
															  .stream()
															  .map(SimpleGrantedAuthority::new)
															  .collect(Collectors.toSet());
							return TokenAuthentication.of(e.getKey(), e.getValue(), authorities);
						}
				)
				.ifPresent(tokenAuthentication -> setSecurityContext(tokenAuthentication, request));

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

	private void setSecurityContext(TokenAuthentication tokenAuthentication, HttpServletRequest request)
	{
		UsernamePasswordAuthenticationToken authToken =
				UsernamePasswordAuthenticationToken.authenticated(tokenAuthentication, tokenAuthentication.token(),
						tokenAuthentication.authorities());

		authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(authToken);
	}

	JwtFilterImpl(final JwtService jwtService)
	{
		this.jwtService = jwtService;
	}

	private record TokenAuthentication(String token, String username, Set<? extends GrantedAuthority> authorities)
			implements UserDetails
	{
		static TokenAuthentication of(final String token, final String username,
									  final Set<? extends GrantedAuthority> authorities)
		{
			return new TokenAuthentication(token, username, authorities);
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities()
		{
			return authorities;
		}

		@Override
		public String getPassword()
		{
			return token;
		}

		@Override
		public String getUsername()
		{
			return username;
		}
	}
}