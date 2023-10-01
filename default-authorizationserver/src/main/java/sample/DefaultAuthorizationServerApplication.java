package sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;

@SpringBootApplication(exclude = OAuth2AuthorizationServerAutoConfiguration.class )
public class DefaultAuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(DefaultAuthorizationServerApplication.class, args);
	}

}
