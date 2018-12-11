/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.serviceprovider.filters;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.metadata.SsoProvider;
import org.springframework.security.saml.serviceprovider.HostedServiceProvider;
import org.springframework.security.saml.serviceprovider.SamlAuthentication;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;

import static java.lang.String.format;
import static org.springframework.util.StringUtils.hasText;

public class ServiceProviderLogoutFilter extends OncePerRequestFilter {

	private static Log logger = LogFactory.getLog(ServiceProviderLogoutFilter.class);

	private final RequestMatcher matcher;
	private final SamlTransformer transformer;
	private final ServiceProviderResolver resolver;
	private final SamlValidator<HostedServiceProvider> validator;
	private LogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();

	public ServiceProviderLogoutFilter(RequestMatcher matcher,
									   SamlTransformer transformer,
									   ServiceProviderResolver resolver,
									   SamlValidator<HostedServiceProvider> validator) {
		this.matcher = matcher;
		this.transformer = transformer;
		this.resolver = resolver;
		this.validator = validator;
	}

	public LogoutSuccessHandler getLogoutSuccessHandler() {
		return logoutSuccessHandler;
	}

	public ServiceProviderLogoutFilter setLogoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {

			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			String logoutRequest = request.getParameter("SAMLRequest");
			String logoutResponse = request.getParameter("SAMLResponse");
			try {
				if (hasText(logoutRequest)) {
					receivedLogoutRequest(request, response, authentication, logoutRequest);
				}
				else if (hasText(logoutResponse)) {
					receivedLogoutResponse(request, response, authentication, logoutResponse);
				}
				else if (authentication instanceof SamlAuthentication) {
					spInitiatedLogout(request, response, authentication);
				}
				else { //just perform a simple logout
					receivedLogoutResponse(request, response, authentication, logoutResponse);
				}
			} catch (IOException x) {
				throw new SamlException(x);
			}
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private void doLogout(HttpServletRequest request,
						  HttpServletResponse response, Authentication authentication) {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.logout(request, response, authentication);
	}

	private void receivedLogoutRequest(HttpServletRequest request,
									   HttpServletResponse response,
									   Authentication authentication,
									   String logoutRequest) throws IOException {
		String xml = transformer.samlDecode(logoutRequest, HttpMethod.GET.name().equalsIgnoreCase(request.getMethod()));
		HostedServiceProvider provider = resolver.resolve(request);
		LogoutRequest lr = transformer.fromXml(
			xml,
			null,
			provider.getConfiguration().getKeys(),
			LogoutRequest.class
		);
		ValidationResult validate = validator.validate(lr, provider);
		if (validate.hasErrors()) {
			throw new SamlException(validate.toString());
		}

		IdentityProviderMetadata idp = provider.getRemoteProvider(lr.getIssuer().getValue());
		LogoutResponse logoutResponse = logoutResponse(provider, lr, idp);
		String url = getRedirectUrl(
			logoutResponse,
			logoutResponse.getDestination(),
			"SAMLResponse",
			request.getParameter("RelayState")
		);
		doLogout(request, response,authentication);
		response.sendRedirect(url);
	}

	private void receivedLogoutResponse(HttpServletRequest request,
										HttpServletResponse response,
										Authentication authentication,
										String logoutResponse) throws IOException, ServletException {
		doLogout(request, response,authentication );
		//TODO - logout success handler invocation
		logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
	}

	private void spInitiatedLogout(HttpServletRequest request,
								   HttpServletResponse response,
								   Authentication authentication) throws IOException {
		if (authentication instanceof SamlAuthentication) {
			SamlAuthentication sa = (SamlAuthentication) authentication;
			logger.debug(format("Initiating SP logout for SP:%s", sa.getHoldingEntityId()));
			HostedServiceProvider provider = resolver.resolve(request);
			ServiceProviderMetadata sp = provider.getMetadata();
			IdentityProviderMetadata idp = provider.getRemoteProvider(sa.getAssertingEntityId());
			LogoutRequest lr = logoutRequest(provider.getMetadata(), idp, (NameIdPrincipal) sa.getSamlPrincipal());
			if (lr.getDestination() != null) {
				logger.debug("Sending logout request through redirect.");
				String redirect = getRedirectUrl(
					lr,
					lr.getDestination().getLocation(),
					"SAMLRequest",
					getLogoutRelayState(
						request,
						idp
					)
				);
				response.sendRedirect(redirect);
			}
			else {
				logger.debug("Unable to send logout request. No destination set.");
			}
		}
	}

	private LogoutRequest logoutRequest(
		ServiceProviderMetadata local,
		IdentityProviderMetadata idp,
		NameIdPrincipal principal) {
		List<SsoProvider> ssoProviders = idp.getSsoProviders();
		LogoutRequest result = new LogoutRequest()
			.setId(UUID.randomUUID().toString())
			.setDestination(
				getPreferredEndpoint(
					ssoProviders.get(0).getSingleLogoutService(),
					null,
					-1
				)
			)
			.setIssuer(new Issuer().setValue(local.getEntityId()))
			.setIssueInstant(DateTime.now())
			.setNameId(principal)
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());

		return result;
	}



	private LogoutResponse logoutResponse(
		HostedServiceProvider local,
		LogoutRequest request,
		IdentityProviderMetadata recipient) {
		List<SsoProvider> ssoProviders = recipient.getSsoProviders();
		Endpoint destination = getPreferredEndpoint(
			ssoProviders.get(0).getSingleLogoutService(),
			null,
			-1
		);
		return new LogoutResponse()
			.setId(UUID.randomUUID().toString())
			.setInResponseTo(request != null ? request.getId() : null)
			.setDestination(destination != null ? destination.getLocation() : null)
			.setStatus(new Status().setCode(StatusCode.SUCCESS))
			.setIssuer(new Issuer().setValue(local.getMetadata().getEntityId()))
			.setSigningKey(
				local.getMetadata().getSigningKey(),
				local.getMetadata().getAlgorithm(),
				local.getMetadata().getDigest()
			)
			.setIssueInstant(new DateTime())
			.setVersion("2.0");
	}


	private String getLogoutRelayState(HttpServletRequest request, IdentityProviderMetadata idp) {
		return null;
	}

	private String getRedirectUrl(Saml2Object lr,
								  String location,
								  String paramName,
								  String relayState)
		throws UnsupportedEncodingException {
		String xml = transformer.toXml(lr);
		String value = transformer.samlEncode(xml, true);
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
		if (hasText(relayState)) {
			builder.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
		}
		return builder.queryParam(paramName, UriUtils.encode(value, StandardCharsets.UTF_8.name()))
			.build()
			.toUriString();
	}

	private Endpoint getPreferredEndpoint(List<Endpoint> endpoints,
										  Binding preferredBinding,
										  int preferredIndex) {
		if (endpoints == null || endpoints.isEmpty()) {
			return null;
		}
		List<Endpoint> eps = endpoints;
		Endpoint result = null;
		//find the preferred binding
		if (preferredBinding != null) {
			for (Endpoint e : eps) {
				if (preferredBinding == e.getBinding()) {
					result = e;
					break;
				}
			}
		}
		//find the configured index
		if (result == null) {
			for (Endpoint e : eps) {
				if (e.getIndex() == preferredIndex) {
					result = e;
					break;
				}
			}
		}
		//find the default endpoint
		if (result == null) {
			for (Endpoint e : eps) {
				if (e.isDefault()) {
					result = e;
					break;
				}
			}
		}
		//fallback to the very first available endpoint
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}
}