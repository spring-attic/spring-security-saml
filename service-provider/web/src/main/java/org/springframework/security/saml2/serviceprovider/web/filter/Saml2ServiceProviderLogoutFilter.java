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

package org.springframework.security.saml2.serviceprovider.web.filter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.Saml2ValidationResult;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.authentication.Saml2Issuer;
import org.springframework.security.saml2.model.authentication.Saml2LogoutResponse;
import org.springframework.security.saml2.model.authentication.Saml2LogoutSaml2Request;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPrincipalSaml2;
import org.springframework.security.saml2.model.authentication.Saml2Status;
import org.springframework.security.saml2.model.authentication.Saml2StatusCode;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2SsoProvider;
import org.springframework.security.saml2.provider.HostedSaml2ServiceProvider;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderResolver;
import org.springframework.security.saml2.serviceprovider.authentication.Saml2Authentication;
import org.springframework.security.saml2.serviceprovider.model.Saml2HttpMessageData;
import org.springframework.security.saml2.serviceprovider.web.util.Saml2ServiceProviderMethods;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;

public class Saml2ServiceProviderLogoutFilter extends OncePerRequestFilter {

	private static Log logger = LogFactory.getLog(Saml2ServiceProviderLogoutFilter.class);

	private LogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
	private final RequestMatcher matcher;
	private final Saml2ServiceProviderMethods saml2SpMethods;
	private final Saml2HttpMessageResponder saml2MessageResponder;

	public Saml2ServiceProviderLogoutFilter(Saml2Transformer transformer,
											Saml2ServiceProviderResolver resolver,
											Saml2ServiceProviderValidator validator,
											RequestMatcher matcher) {
		this(
			transformer,
			resolver,
			validator,
			matcher,
			new DefaultRedirectStrategy()
		);
	}

	public Saml2ServiceProviderLogoutFilter(Saml2Transformer transformer,
											Saml2ServiceProviderResolver resolver,
											Saml2ServiceProviderValidator validator,
											RequestMatcher matcher,
											RedirectStrategy redirectStrategy) {
		this.matcher = matcher;
		this.saml2SpMethods = new Saml2ServiceProviderMethods(transformer, resolver, validator);
		this.saml2MessageResponder = new Saml2HttpMessageResponder(saml2SpMethods, redirectStrategy);
	}

	public LogoutSuccessHandler getLogoutSuccessHandler() {
		return logoutSuccessHandler;
	}

	public Saml2ServiceProviderLogoutFilter setLogoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			doSaml2LogoutAction(request, response);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	private void doSaml2LogoutAction(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Saml2Object logoutRequest = saml2SpMethods.getSamlRequest(request);
		Saml2Object logoutResponse = saml2SpMethods.getSamlResponse(request);
		if (ofNullable(logoutRequest).isPresent()) {
			receivedLogoutRequest(request, response, authentication, logoutRequest);
		}
		else if (ofNullable(logoutResponse).isPresent()) {
			finishLogout(request, response, authentication, logoutResponse);
		}
		else if (authentication instanceof Saml2Authentication) {
			spInitiatedLogout(request, response, authentication);
		}
		else {
			//just perform a simple logout
			finishLogout(request, response, authentication, null);
		}
	}

	private void receivedLogoutRequest(HttpServletRequest request,
									   HttpServletResponse response,
									   Authentication authentication,
									   Saml2Object logoutRequest) throws IOException {

		if (!(logoutRequest instanceof Saml2LogoutSaml2Request)) {
			throw new Saml2Exception("Invalid logout request:" + logoutRequest);
		}
		Saml2LogoutSaml2Request lr = (Saml2LogoutSaml2Request) logoutRequest;
		HostedSaml2ServiceProvider provider = saml2SpMethods.getProvider(request);
		Saml2ValidationResult validate = saml2SpMethods.getValidator().validate(lr, provider);
		if (validate.hasErrors()) {
			throw new Saml2Exception(validate.toString());
		}

		Saml2IdentityProviderMetadata idp = provider.getRemoteProvider(lr.getIssuer().getValue());
		Saml2LogoutResponse logoutResponse = logoutResponse(provider, lr, idp);
		Saml2HttpMessageData mvcData = new Saml2HttpMessageData(
			null,
			logoutResponse,
			new Saml2Endpoint()
				.setLocation(logoutResponse.getDestination())
				.setBinding(Saml2Binding.REDIRECT),
			getLogoutRelayState(request, idp)
		);
		saml2MessageResponder.processResponse(
			mvcData,
			request,
			response
		);
		doLogout(request, response, authentication);
	}

	private void finishLogout(HttpServletRequest request,
							  HttpServletResponse response,
							  Authentication authentication,
							  Saml2Object logoutResponse) throws IOException, ServletException {
		doLogout(request, response, authentication);
		logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
	}

	private void spInitiatedLogout(HttpServletRequest request,
								   HttpServletResponse response,
								   Authentication authentication) throws IOException {
		if (authentication instanceof Saml2Authentication) {
			Saml2Authentication sa = (Saml2Authentication) authentication;
			logger.debug(format("Initiating SP logout for SP:%s", sa.getHoldingEntityId()));
			HostedSaml2ServiceProvider provider = saml2SpMethods.getProvider(request);
			Saml2ServiceProviderMetadata sp = provider.getMetadata();
			Saml2IdentityProviderMetadata idp = provider.getRemoteProvider(sa.getAssertingEntityId());
			Saml2LogoutSaml2Request lr = logoutRequest(provider.getMetadata(), idp, (Saml2NameIdPrincipalSaml2) sa.getSamlPrincipal());
			if (lr.getDestination() != null) {
				logger.debug("Sending logout request through redirect.");
				Saml2HttpMessageData mvcData = new Saml2HttpMessageData(
					lr,
					null,
					lr.getDestination(),
					getLogoutRelayState(
						request,
						idp
					)
				);
				saml2MessageResponder.processResponse(
					mvcData,
					request,
					response
				);
			}
			else {
				throw new Saml2Exception("Unable to send logout request. No destination set.");
			}
		}
	}

	private Saml2LogoutResponse logoutResponse(
		HostedSaml2ServiceProvider local,
		Saml2LogoutSaml2Request request,
		Saml2IdentityProviderMetadata recipient) {
		List<Saml2SsoProvider> ssoProviders = recipient.getSsoProviders();
		Saml2Endpoint destination = saml2SpMethods.getPreferredEndpoint(
			ssoProviders.get(0).getSingleLogoutService(),
			null,
			-1
		);
		return new Saml2LogoutResponse()
			.setId("LRP" + UUID.randomUUID().toString())
			.setInResponseTo(request != null ? request.getId() : null)
			.setDestination(destination != null ? destination.getLocation() : null)
			.setStatus(new Saml2Status().setCode(Saml2StatusCode.SUCCESS))
			.setIssuer(new Saml2Issuer().setValue(local.getMetadata().getEntityId()))
			.setSigningKey(
				local.getMetadata().getSigningKey(),
				local.getMetadata().getAlgorithm(),
				local.getMetadata().getDigest()
			)
			.setIssueInstant(new DateTime())
			.setVersion("2.0");
	}

	private void doLogout(HttpServletRequest request,
						  HttpServletResponse response, Authentication authentication) {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.logout(request, response, authentication);
	}

	private Saml2LogoutSaml2Request logoutRequest(
		Saml2ServiceProviderMetadata local,
		Saml2IdentityProviderMetadata idp,
		Saml2NameIdPrincipalSaml2 principal) {
		List<Saml2SsoProvider> ssoProviders = idp.getSsoProviders();
		Saml2LogoutSaml2Request result = new Saml2LogoutSaml2Request()
			.setId("LRQ" + UUID.randomUUID().toString())
			.setDestination(
				saml2SpMethods.getPreferredEndpoint(
					ssoProviders.get(0).getSingleLogoutService(),
					null,
					-1
				)
			)
			.setIssuer(new Saml2Issuer().setValue(local.getEntityId()))
			.setIssueInstant(DateTime.now())
			.setNameId(principal)
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());

		return result;
	}

	private String getLogoutRelayState(HttpServletRequest request, Saml2IdentityProviderMetadata idp) {
		return request.getParameter("RelayState");
	}

}
