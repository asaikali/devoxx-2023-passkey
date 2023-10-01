package sample.config;

import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		// @formatter:off
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		// @formatter:on

		// @formatter:off
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer(oauth2ResourceServer ->
				oauth2ResourceServer.jwt(Customizer.withDefaults()));
		// @formatter:on

		return http.build();
	}

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
