/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.serviceprovider.web.filters;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml.model.Saml2Object;
import org.springframework.security.saml.model.authentication.Issuer;
import org.springframework.security.saml.model.authentication.LogoutRequest;
import org.springframework.security.saml.model.authentication.LogoutResponse;
import org.springframework.security.saml.model.authentication.NameIdPrincipal;
import org.springframework.security.saml.model.authentication.Status;
import org.springframework.security.saml.model.authentication.StatusCode;
import org.springframework.security.saml.model.metadata.Endpoint;
import org.springframework.security.saml.model.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.model.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.model.metadata.SsoProvider;
import org.springframework.security.saml.serviceprovider.authentication.SamlAuthentication;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class ServiceProviderLogoutFilter extends AbstractSamlServiceProviderFilter {

	private static Log logger = LogFactory.getLog(ServiceProviderLogoutFilter.class);

	private LogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();

	public ServiceProviderLogoutFilter(SamlTransformer transformer,
									   ServiceProviderResolver resolver,
									   ServiceProviderValidator validator,
									   RequestMatcher matcher) {
		super(transformer, resolver, validator, matcher);
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
		if (getMatcher().matches(request)) {

			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			Saml2Object logoutRequest = getSpUtils().getSamlRequest(request);
			Saml2Object logoutResponse = getSpUtils().getSamlResponse(request);
			try {

				if (ofNullable(logoutRequest).isPresent()) {
					receivedLogoutRequest(request, response, authentication, logoutRequest);
				}
				else if (ofNullable(logoutResponse).isPresent()) {
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

	protected void receivedLogoutRequest(HttpServletRequest request,
										 HttpServletResponse response,
										 Authentication authentication,
										 Saml2Object logoutRequest) throws IOException {

		if (!(logoutRequest instanceof LogoutRequest)) {
			throw new SamlException("Invalid logout request:" + logoutRequest);
		}
		LogoutRequest lr = (LogoutRequest) logoutRequest;
		HostedServiceProvider provider = getSpUtils().getProvider(request);
		ValidationResult validate = getValidator().validate(lr, provider);
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
		doLogout(request, response, authentication);
		response.sendRedirect(url);
	}

	protected void receivedLogoutResponse(HttpServletRequest request,
										  HttpServletResponse response,
										  Authentication authentication,
										  Saml2Object logoutResponse) throws IOException, ServletException {
		doLogout(request, response, authentication);
		logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
	}

	protected void spInitiatedLogout(HttpServletRequest request,
									 HttpServletResponse response,
									 Authentication authentication) throws IOException {
		if (authentication instanceof SamlAuthentication) {
			SamlAuthentication sa = (SamlAuthentication) authentication;
			logger.debug(format("Initiating SP logout for SP:%s", sa.getHoldingEntityId()));
			HostedServiceProvider provider = getSpUtils().getProvider(request);
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

	protected LogoutResponse logoutResponse(
		HostedServiceProvider local,
		LogoutRequest request,
		IdentityProviderMetadata recipient) {
		List<SsoProvider> ssoProviders = recipient.getSsoProviders();
		Endpoint destination = getSpUtils().getPreferredEndpoint(
			ssoProviders.get(0).getSingleLogoutService(),
			null,
			-1
		);
		return new LogoutResponse()
			.setId("LRP" + UUID.randomUUID().toString())
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

	protected String getRedirectUrl(Saml2Object lr,
									String location,
									String paramName,
									String relayState)
		throws UnsupportedEncodingException {
		String xml = getTransformer().toXml(lr);
		String value = getTransformer().samlEncode(xml, true);
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
		if (hasText(relayState)) {
			builder.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
		}
		return builder.queryParam(paramName, UriUtils.encode(value, StandardCharsets.UTF_8.name()))
			.build()
			.toUriString();
	}

	protected void doLogout(HttpServletRequest request,
							HttpServletResponse response, Authentication authentication) {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.logout(request, response, authentication);
	}

	protected LogoutRequest logoutRequest(
		ServiceProviderMetadata local,
		IdentityProviderMetadata idp,
		NameIdPrincipal principal) {
		List<SsoProvider> ssoProviders = idp.getSsoProviders();
		LogoutRequest result = new LogoutRequest()
			.setId("LRQ" + UUID.randomUUID().toString())
			.setDestination(
				getSpUtils().getPreferredEndpoint(
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

	protected String getLogoutRelayState(HttpServletRequest request, IdentityProviderMetadata idp) {
		return request.getParameter("RelayState");
	}
}
