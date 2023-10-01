package sample.config;

import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		// @formatter:off
		return AuthorizationServerSettings.builder()
				.authorizationEndpoint("/oauth2/v1/authorize")
				.tokenEndpoint("/oauth2/v1/token")
				.tokenIntrospectionEndpoint("/oauth2/v1/introspect")
				.tokenRevocationEndpoint("/oauth2/v1/revoke")
				.build();
		// @formatter:on
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					Set<String> authorities = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities());
					claims.put("authorities", authorities);
				});
			}
		};
	}

	@Bean
	public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueTokenCustomizer() {
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					Set<String> authorities = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities());
					claims.put("authorities", authorities);
				});
			}
		};
	}

}
