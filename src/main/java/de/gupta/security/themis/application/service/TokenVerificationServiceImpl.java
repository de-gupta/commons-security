package de.gupta.security.themis.application.service;

import de.gupta.aletheia.functional.Unfolding;
import de.gupta.aletheia.trials.Fallible;
import de.gupta.aletheia.trials.Portent;
import de.gupta.commons.utility.string.StringSanitizationUtility;
import de.gupta.security.themis.api.TokenVerificationConfiguration;
import de.gupta.security.themis.api.TokenVerificationPolicy;
import de.gupta.security.themis.domain.model.*;
import de.gupta.security.themis.utility.TokenUtility;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

final class TokenVerificationServiceImpl implements TokenVerificationService
{
	private final JwtParser jwtParser;

	static TokenVerificationService create(final JwtParser jwtParser)
	{
		Objects.requireNonNull(jwtParser, "jwtParser must not be null");
		return new TokenVerificationServiceImpl(jwtParser);
	}

	@Override
	public VerificationResult verifyToken(final VerificationRequest request)
	{
		return Fallible.beckon(request)
		               .metamorphose(this::verifySignedToken, exceptionally())
		               .coronate(Function.identity(), _ -> failure(VerificationFailureReason.MALFORMED));
	}

	private VerificationResult verifySignedToken(final VerificationRequest request)
	{
		final TokenVerificationConfiguration configuration = request.configuration();
		final TokenVerificationPolicy policy = configuration.policy();
		final Jws<Claims> jws = jwtParser.parseSignedClaims(request.token());
		final Claims claims = jws.getPayload();

		return validateClaims(claims, policy)
				.<VerificationResult>metamorphose(Function.identity())
				.infuse(VerificationSuccess.of(
						NormalizedTokenFactory.of(request.token(), claims,
								configuration.rolesClaimName(),
								configuration.versionClaimName())));
	}

	private List<Portent<VerificationResult>> exceptionally()
	{
		return List.of(
				Portent.foretell(ExpiredJwtException.class, _ -> failure(VerificationFailureReason.EXPIRED)),
				Portent.foretell(PrematureJwtException.class, _ -> failure(VerificationFailureReason.NOT_YET_VALID)),
				Portent.foretell(SecurityException.class, _ -> failure(VerificationFailureReason.INVALID_SIGNATURE)),
				Portent.foretell(UnsupportedJwtException.class, _ -> failure(VerificationFailureReason.UNSUPPORTED)),
				Portent.foretell(MalformedJwtException.class, _ -> failure(VerificationFailureReason.MALFORMED)),
				Portent.foretell(IllegalArgumentException.class, _ -> failure(VerificationFailureReason.MALFORMED)),
				Portent.foretell(JwtException.class, _ -> failure(VerificationFailureReason.MALFORMED)));
	}

	private Unfolding<VerificationFailure> validateClaims(final Claims claims, final TokenVerificationPolicy policy)
	{
		return Unfolding.beckon(claims)
		                .convoke(List.of(
										presentClaims -> validateSubject(presentClaims, policy),
										presentClaims -> validateIssuer(presentClaims, policy),
										presentClaims -> validateAudience(presentClaims, policy)),
								(Collection<? extends Unfolding<VerificationFailure>> verdicts) ->
										verdicts.stream()
						                        .flatMap(Unfolding::stream)
						                        .findFirst()
						                        .orElse(null));
	}

	private Unfolding<VerificationFailure> validateSubject(final Claims claims, final TokenVerificationPolicy policy)
	{
		return Unfolding.beckon(policy)
		                .discern(TokenVerificationPolicy::requireSubject)
		                .discern(_ -> StringSanitizationUtility.isAbsentOrBlank(claims.getSubject()))
		                .metamorphose(_ -> failure(VerificationFailureReason.MISSING_SUBJECT));
	}

	private Unfolding<VerificationFailure> validateIssuer(final Claims claims, final TokenVerificationPolicy policy)
	{
		return Unfolding.augur(policy.expectedIssuer())
		                .evolve(expectedIssuer -> !expectedIssuer.equals(claims.getIssuer()),
								_ -> failure(VerificationFailureReason.INVALID_ISSUER));
	}

	private Unfolding<VerificationFailure> validateAudience(final Claims claims, final TokenVerificationPolicy policy)
	{
		return Unfolding.beckon(policy.expectedAudiences())
		                .discern(e -> !e.isEmpty())
		                .evolve(e -> !TokenUtility.audiencesOf(claims).containsAll(e),
								_ -> failure(VerificationFailureReason.INVALID_AUDIENCE));
	}

	private VerificationFailure failure(final VerificationFailureReason reason)
	{
		return VerificationFailure.of(reason);
	}

	private TokenVerificationServiceImpl(final JwtParser jwtParser)
	{
		this.jwtParser = jwtParser;
	}
}
