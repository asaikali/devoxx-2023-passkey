package sample.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

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
					.opaqueToken(Customizer.withDefaults())
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

}
