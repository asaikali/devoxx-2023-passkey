package sample.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.webauthn.rp.config.annotation.web.configurers.WebAuthnRelyingPartyConfigurer;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

	// @formatter:off
	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(
			HttpSecurity http,
			MvcRequestMatcher.Builder mvcRequestMatcher) throws Exception {

		http
			.authorizeHttpRequests((authorize) ->
				authorize
					.requestMatchers(
							mvcRequestMatcher.pattern("/"),
							mvcRequestMatcher.pattern("/index"),
							mvcRequestMatcher.pattern("/register"),
							mvcRequestMatcher.pattern("/webauthn/register"),
							mvcRequestMatcher.pattern("/webauthn/login"),
							PathRequest.toStaticResources().atCommonLocations(),
							PathRequest.toH2Console()
					).permitAll()
					.anyRequest().authenticated()
			)
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(Customizer.withDefaults())
			.apply(new WebAuthnRelyingPartyConfigurer());

		return http.build();
	}
	// @formatter:on

	// @formatter:off
	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("user", "admin")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
	// @formatter:on

	@Bean
	public MvcRequestMatcher.Builder mvcRequestMatcher(HandlerMappingIntrospector introspector) {
		return new MvcRequestMatcher.Builder(introspector);
	}

}
