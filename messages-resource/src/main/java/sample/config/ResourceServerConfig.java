package sample.config;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.CollectionUtils;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

	// @formatter:off
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.securityMatcher("/messages/**")
				.authorizeHttpRequests(authorize ->
					authorize
						.requestMatchers("/messages/**").hasAnyAuthority("SCOPE_message.read", "ROLE_user")
			)
			.oauth2ResourceServer(resourceServer ->
				resourceServer
					.opaqueToken(opaqueToken ->
						opaqueToken.authenticationConverter(opaqueTokenAuthenticationConverter()))
			);
		return http.build();
	}
	// @formatter:on

	private JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter());
		return jwtAuthenticationConverter;
	}

	private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter() {
		// Use 'scope' or 'scp' claim (the default) to extract authorities
		JwtGrantedAuthoritiesConverter defaultAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

		// Use 'authorities' claim to extract authorities
		JwtGrantedAuthoritiesConverter customAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		customAuthoritiesConverter.setAuthorityPrefix("");
		customAuthoritiesConverter.setAuthoritiesClaimName("authorities");

		return (jwt) -> {
			List<GrantedAuthority> authorities = new ArrayList<>();
			authorities.addAll(defaultAuthoritiesConverter.convert(jwt));
			authorities.addAll(customAuthoritiesConverter.convert(jwt));
			return authorities;
		};
	}

	private OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter() {
		return (introspectedToken, authenticatedPrincipal) -> {
			Instant iat = authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT);
			Instant exp = authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP);
			OAuth2AccessToken accessToken = new OAuth2AccessToken(
					OAuth2AccessToken.TokenType.BEARER, introspectedToken, iat, exp);

			List<GrantedAuthority> authorities = extractAuthoritiesFromClaims(authenticatedPrincipal);

			return new BearerTokenAuthentication(authenticatedPrincipal, accessToken, authorities);
		};
	}

	private List<GrantedAuthority> extractAuthoritiesFromClaims(OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
		List<GrantedAuthority> authorities = new ArrayList<>();

		List<String> scopeClaim = authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.SCOPE);
		if (!CollectionUtils.isEmpty(scopeClaim)) {
			scopeClaim.forEach(scope -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope)));
		}

		List<String> authoritiesClaim = authenticatedPrincipal.getAttribute("authorities");
		if (!CollectionUtils.isEmpty(authoritiesClaim)) {
			authoritiesClaim.forEach(authority -> authorities.add(new SimpleGrantedAuthority(authority)));
		}

		return authorities;
	}

}
