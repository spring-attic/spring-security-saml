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

package org.springframework.security.saml.spi;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalProviderConfiguration;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static org.springframework.util.StringUtils.hasText;

public class DefaultLogoutHandler extends DefaultSamlMessageHandler<DefaultLogoutHandler> {

	private SamlValidator validator;
	private String postBindingTemplate;
	private DefaultSessionAssertionStore assertionStore;
	private final String ATTRIBUTE_NAME = getClass().getName() + ".logout.request";

	public SamlValidator getValidator() {
		return validator;
	}

	public DefaultLogoutHandler setValidator(SamlValidator validator) {
		this.validator = validator;
		return this;
	}

	public DefaultSessionAssertionStore getAssertionStore() {
		return assertionStore;
	}

	public DefaultLogoutHandler setAssertionStore(DefaultSessionAssertionStore assertionStore) {
		this.assertionStore = assertionStore;
		return this;
	}

	public String getPostBindingTemplate() {
		return postBindingTemplate;
	}

	public DefaultLogoutHandler setPostBindingTemplate(String postBindingTemplate) {
		this.postBindingTemplate = postBindingTemplate;
		return this;
	}


	@Override
	public ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException, ServletException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String prequest = request.getParameter("SAMLRequest");
		String presponse = request.getParameter("SAMLResponse");
		if (hasText(prequest)) {
			//we received a request
			logger.debug(format("Received logout request:%s", prequest));
			prequest = getTransformer().samlDecode(prequest, HttpMethod.GET.matches(request.getMethod()));
			LogoutRequest logoutRequest = (LogoutRequest) getTransformer().fromXml(prequest, null, null);
			getValidator().validate(logoutRequest, getResolver(), request);
			return logoutRequested(authentication, logoutRequest, request, response);
		}
		else if (hasText(presponse)) {
			//we received a response
			logger.debug(format("Received logout response:%s", presponse));
			presponse = getTransformer().samlDecode(presponse, HttpMethod.GET.matches(request.getMethod()));
			LogoutResponse logoutResponse = (LogoutResponse) getTransformer().fromXml(presponse, null, null);
			getValidator().validate(logoutResponse, getResolver(), request);
			return logoutCompleted(authentication, logoutResponse, request, response);
		}
		LocalProviderConfiguration<? extends LocalProviderConfiguration> provider = getTargetProvider(request);
		if (provider instanceof LocalServiceProviderConfiguration) {
			logger.debug(format("Logout initiated without a target for the local service provider."));
			if (authentication instanceof SamlAuthentication) {
				SamlAuthentication sa = (SamlAuthentication) authentication;
				logger.debug(format("Initiating SP logout for SP:%s", sa.getHoldingEntityId()));
				if (logoutSpInitiated(request, response, sa)) {
					return ProcessingStatus.STOP;
				}
			}
			else {
				logger.debug(format("Unrecognized SP authentication:'%s' - completing logout", authentication));
				return logoutCompleted(authentication, null, request, response);
			}
		}
		else if (provider instanceof LocalIdentityProviderConfiguration) {
			logger.debug(format("Logout initiated without a target for the local identity provider."));
			if (logoutIdpInitiated(request, response, authentication)) {
				return ProcessingStatus.STOP;
			}
		}
		return ProcessingStatus.CONTINUE;
	}

	protected boolean logoutIdpInitiated(HttpServletRequest request,
										 HttpServletResponse response,
										 Authentication sa) throws IOException, ServletException {
		Assertion issuedAssertion = getAssertionStore().removeFirst(request);
		if (issuedAssertion == null) {
			logger.debug("IDP initiated logout. empty assertion store.");
			LogoutRequest initial = getInitialSpRequest(request);
			logger.debug(format("Found initial SP request:%s", initial));
			sessionLogout(request, response, sa);
			//was this initiated by an SP? Do we have a response ready?
			if (initial == null) {
				String localRedirect = getLocalLogoutRedirect(request);
				logger.debug(format("Sending logout redirect to:%s", localRedirect));
				response.sendRedirect(localRedirect);
				return true;
			}
			else {
				return logoutRequested(sa, initial, request, response) == ProcessingStatus.STOP;
			}
		}
		else if (sa != null) {
			IdentityProviderMetadata idp = getResolver()
				.getLocalIdentityProvider(getNetwork().getBasePath(request));
			ServiceProviderMetadata sp = getResolver().resolveServiceProvider(issuedAssertion);
			NameIdPrincipal principal = sa instanceof SamlAuthentication ?
				(NameIdPrincipal) ((SamlAuthentication) sa).getSamlPrincipal() :
				new NameIdPrincipal()
					.setValue(sa.getPrincipal().toString())
					.setFormat(NameId.UNSPECIFIED);
			LogoutRequest lr = getDefaults().logoutRequest(
				sp,
				idp,
				principal
			);
			if (lr.getDestination() != null) {
				String redirect = getRedirectUrl(lr, lr.getDestination().getLocation(), "SAMLRequest");
				response.sendRedirect(redirect);
				return true;
			}
		}
		sessionLogout(request, response, null);
		return false;
	}

	protected String getLocalLogoutRedirect(HttpServletRequest request) {
		return getNetwork().getBasePath(request) + "/";
	}

	protected LogoutRequest getInitialSpRequest(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return null;
		} else {
			return (LogoutRequest) session.getAttribute(ATTRIBUTE_NAME);
		}
	}

	protected void setInitialSpRequest(HttpServletRequest request, LogoutRequest lr) {
		if (lr != null) {
			request.getSession(true).setAttribute(ATTRIBUTE_NAME, lr);
		}
	}

	protected boolean logoutSpInitiated(HttpServletRequest request,
										HttpServletResponse response,
										SamlAuthentication sa) throws IOException {
		ServiceProviderMetadata sp = getResolver().getLocalServiceProvider(
			getNetwork().getBasePath(request)
		);
		IdentityProviderMetadata idp = getResolver().resolveIdentityProvider(sa.getAssertingEntityId());
		LogoutRequest lr = getDefaults().logoutRequest(
			idp,
			sp,
			(NameIdPrincipal) sa.getSamlPrincipal()
		);
		if (lr.getDestination() != null) {
			String redirect = getRedirectUrl(lr, lr.getDestination().getLocation(), "SAMLRequest");
			response.sendRedirect(redirect);
			return true;
		}
		return false;
	}

	protected ProcessingStatus logoutCompleted(Authentication authentication,
											   LogoutResponse logoutResponse,
											   HttpServletRequest request,
											   HttpServletResponse response) throws IOException, ServletException {
		LocalProviderConfiguration<? extends LocalProviderConfiguration> provider = getTargetProvider(request);
		if (provider instanceof LocalServiceProviderConfiguration) {
			sessionLogout(request, response, authentication);
			response.sendRedirect(getLocalLogoutRedirect(request));
			return ProcessingStatus.STOP;
		}
		else if (provider instanceof LocalIdentityProviderConfiguration) {
			//send the next request
			if (logoutIdpInitiated(request, response, authentication)) {
				return ProcessingStatus.STOP;
			}
		}
		return ProcessingStatus.CONTINUE;
	}

	protected ProcessingStatus logoutRequested(Authentication authentication,
											   LogoutRequest logoutRequest,
											   HttpServletRequest request,
											   HttpServletResponse response) throws IOException, ServletException {
		LocalProviderConfiguration<? extends LocalProviderConfiguration> provider = getTargetProvider(request);
		if (provider instanceof LocalServiceProviderConfiguration) {
			ServiceProviderMetadata localSp = getResolver().getLocalServiceProvider(getNetwork().getBasePath(request));
			IdentityProviderMetadata idp = getResolver().resolveIdentityProvider(logoutRequest);
			logger.debug(
				format("Processing logout request for local SP:%s to IDP:%s",localSp.getEntityId(),idp.getEntityId())
			);
			LogoutResponse lr = getDefaults().logoutResponse(logoutRequest, idp, localSp);
			String url = getRedirectUrl(lr, lr.getDestination(), "SAMLResponse");
			sessionLogout(request, response, authentication);
			logger.debug(format("Local SP logout complete. Redirecting to:%s", url));
			response.sendRedirect(url);
			return ProcessingStatus.STOP;
		}
		else if (provider instanceof LocalIdentityProviderConfiguration) {
			logger.debug("Local IDP received logout request.");
			if (idpHasOtherSessions(request,logoutRequest)) {
				logger.debug("Multiple SP sessions present, starting logout sequence.");
				setInitialSpRequest(request, logoutRequest);
				if (logoutIdpInitiated(request, response, authentication)) {
					return ProcessingStatus.STOP;
				}
			} else {
				logger.debug("No SP sessions found, returning logout response");
				IdentityProviderMetadata local =
					getResolver().getLocalIdentityProvider(getNetwork().getBasePath(request));
				ServiceProviderMetadata sp = getResolver().resolveServiceProvider(logoutRequest);
				LogoutResponse lr = getDefaults().logoutResponse(logoutRequest, sp, local);
				String url = getRedirectUrl(lr, lr.getDestination(), "SAMLResponse");
				sessionLogout(request, response, authentication);
				response.sendRedirect(url);
				return ProcessingStatus.STOP;
			}
		}
		logger.warn(format("Unable to process logout request:%s",logoutRequest));
		return ProcessingStatus.CONTINUE;
	}

	protected boolean idpHasOtherSessions(HttpServletRequest request, LogoutRequest lr) {
		List<Assertion> assertions = getAssertionStore().getMessages(request);
		if (assertions.size() > 1) {
			return true;
		} else if (assertions.size() == 1) {
			String assertionEntityId = assertions.get(0).getSubject().getPrincipal().getSpNameQualifier();
			String lrEntityId = lr.getIssuer().getValue();
			return !assertionEntityId.equals(lrEntityId);
		} else {
			return false;
		}
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		return getTargetProvider(request) != null;
	}

	protected boolean internalSupports(HttpServletRequest request, LocalProviderConfiguration provider) {
		boolean result = false;
		if (provider != null && provider.isSingleLogoutEnabled()) {
			String path = getExpectedPath(provider,"logout");
			result = isUrlMatch(request, path);
		}
		return result;
	}

	protected LocalProviderConfiguration<? extends LocalProviderConfiguration> getTargetProvider(HttpServletRequest request) {
		for (LocalProviderConfiguration<? extends LocalProviderConfiguration> provider :
			asList(getConfiguration().getServiceProvider(), getConfiguration().getIdentityProvider())) {
			if (internalSupports(request, provider)) {
				return provider;
			}
		}
		return null;
	}

	protected void sessionLogout(HttpServletRequest request,
								 HttpServletResponse response,
								 Authentication authentication) {
		logger.debug(format("Performing local session logout for authentication:%s", authentication));
		if (authentication != null) {
			new SecurityContextLogoutHandler()
				.logout(request, response, authentication);
		}
		SecurityContextHolder.getContext().setAuthentication(null);
	}

	protected String getRedirectUrl(Saml2Object lr, String location, String paramName)
		throws UnsupportedEncodingException {
		String xml = getTransformer().toXml(lr);
		String value = getTransformer().samlEncode(xml, true);
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
		return builder.queryParam(paramName, UriUtils.encode(value, StandardCharsets.UTF_8.name()))
			.build()
			.toUriString();
	}

}
