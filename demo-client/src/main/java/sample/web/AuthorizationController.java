package sample.web;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class AuthorizationController {
	private final WebClient webClient;
	private final String messagesBaseUri;

	public AuthorizationController(WebClient webClient,
			@Value("${messages.base-uri}") String messagesBaseUri) {
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code")
	public String authorizationCodeGrant(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
					OAuth2AuthorizedClient authorizedClient) {

		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);
		model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());

		return "index";
	}

	@GetMapping(value = "/revoke", params = "grant_type=authorization_code")
	public String revokeAuthorizationCodeGrantToken(
			@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
			OAuth2AuthorizedClient authorizedClient) {

		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		String revocationEndpointUri = getRevocationEndpointUri(clientRegistration);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.TOKEN, authorizedClient.getAccessToken().getTokenValue());
		parameters.add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "access_token");

		this.webClient
				.post()
				.uri(revocationEndpointUri)
				.headers((headers) -> headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret()))
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromFormData(parameters))
				.retrieve()
				.bodyToMono(Void.class)
				.block();

		return "index";
	}

	// '/authorized' is the registered 'redirect_uri' for authorization_code
	@GetMapping(value = "/authorized", params = OAuth2ParameterNames.ERROR)
	public String authorizationFailed(Model model, HttpServletRequest request) {
		String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
		if (StringUtils.hasText(errorCode)) {
			model.addAttribute("error",
					new OAuth2Error(
							errorCode,
							request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION),
							request.getParameter(OAuth2ParameterNames.ERROR_URI))
			);
		}

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials")
	public String clientCredentialsGrant(Model model,
										 @RegisteredOAuth2AuthorizedClient("messaging-client-client-credentials")
										 OAuth2AuthorizedClient authorizedClient) {

		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);
		model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());

		return "index";
	}

	@GetMapping(value = "/revoke", params = "grant_type=client_credentials")
	public String revokeClientCredentialsGrantToken(
			@RegisteredOAuth2AuthorizedClient("messaging-client-client-credentials")
			OAuth2AuthorizedClient authorizedClient) {

		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		String revocationEndpointUri = getRevocationEndpointUri(clientRegistration);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.TOKEN, authorizedClient.getAccessToken().getTokenValue());
		parameters.add(OAuth2ParameterNames.TOKEN_TYPE_HINT, "access_token");

		this.webClient
				.post()
				.uri(revocationEndpointUri)
				.headers((headers) -> headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret()))
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromFormData(parameters))
				.retrieve()
				.bodyToMono(Void.class)
				.block();

		return "index";
	}

	@ExceptionHandler(WebClientResponseException.class)
	public String handleError(Model model, WebClientResponseException ex) {
		model.addAttribute("error", ex.getMessage());
		return "index";
	}

	private String getRevocationEndpointUri(ClientRegistration clientRegistration) {
		Map<String, Object> configurationMetadata = clientRegistration.getProviderDetails().getConfigurationMetadata();
		return (String) configurationMetadata.get("revocation_endpoint");
	}

}
