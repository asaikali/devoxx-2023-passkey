package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

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

}
