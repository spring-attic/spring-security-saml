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

package org.springframework.security.saml.spi.deprecated;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultSessionAssertionStore;

import static java.lang.String.format;
import static org.springframework.http.HttpMethod.GET;

public class DefaultIdpRequestHandler extends IdpAssertionHandler<DefaultIdpRequestHandler> {

	private SamlValidator validator;
	private String postBindingTemplate;
	private DefaultSessionAssertionStore store;

	public String getPostBindingTemplate() {
		return postBindingTemplate;
	}

	public DefaultIdpRequestHandler setPostBindingTemplate(String postBindingTemplate) {
		this.postBindingTemplate = postBindingTemplate;
		return this;
	}

	public DefaultSessionAssertionStore getStore() {
		return store;
	}

	public DefaultIdpRequestHandler setStore(DefaultSessionAssertionStore store) {
		this.store = store;
		return this;
	}

	public SamlValidator getValidator() {
		return validator;
	}

	public DefaultIdpRequestHandler setValidator(SamlValidator validator) {
		this.validator = validator;
		return this;
	}


	@Override
	public ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException {

		IdentityProviderMetadata local = getLocalIdentityProvider(request);
		String resp = getSamlRequest(request);
		logger.debug(format("Local IDP(%s) received SAMLRequest", local.getEntityId()));
		//receive authentication request
		String xml = decodeXml(request, resp);
		//extract basic data so we can map it to an IDP
		List<SimpleKey> localKeys = local.getIdentityProvider().getKeys();
		AuthenticationRequest authn = getAuthenticationRequest(xml, localKeys, null);
		ServiceProviderMetadata sp = getServiceProvider(authn);
		logger.debug(format("Resolved AuthnRequest to SP:%s", sp.getEntityId()));
		//validate signature
		authn = getAuthenticationRequest(xml, localKeys, sp.getServiceProvider().getKeys());
		getValidator().validate(authn, getResolver(), request);
		//create the assertion
		Assertion assertion = getAssertion(
			local,
			authn,
			sp,
			SecurityContextHolder.getContext().getAuthentication(),
			request,
			store
		);
		Response result = getResponse(local, authn, sp, assertion);
		String encoded = encodeResponse(result);
		String destination = getACS(authn, local, sp);

		Map<String, String> model = new HashMap<>();
		logger.debug(format("Submitting assertion for SP:%s to URL:%s", sp.getEntityId(), destination));
		model.put("action", destination);
		model.put("SAMLResponse", encoded);
		processHtml(request, response, getPostBindingTemplate(), model);
		return ProcessingStatus.STOP;
	}

	protected ServiceProviderMetadata getServiceProvider(AuthenticationRequest authn) {
		return getResolver().resolveServiceProvider(authn);
	}

	protected String getACS(AuthenticationRequest authn, IdentityProviderMetadata idp, ServiceProviderMetadata sp) {
		return authn.getAssertionConsumerService().getLocation();
	}

	protected String encodeResponse(Response result) {
		return getTransformer().samlEncode(getTransformer().toXml(result), false);
	}

	protected AuthenticationRequest getAuthenticationRequest(String xml,
															 List<SimpleKey> localKeys,
															 List<SimpleKey> verificationKeys) {
		return (AuthenticationRequest) getTransformer().fromXml(xml, verificationKeys, localKeys);
	}

	protected String decodeXml(HttpServletRequest request, String resp) {
		return getTransformer().samlDecode(resp, GET.matches(request.getMethod()));
	}

	protected String getSamlRequest(HttpServletRequest request) {
		return request.getParameter("SAMLRequest");
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		LocalIdentityProviderConfiguration idp = getConfiguration().getIdentityProvider();
		String path = getExpectedPath(idp,"SSO");
		return isUrlMatch(request, path) && getSamlRequest(request) != null;
	}


	protected Response getResponse(IdentityProviderMetadata local,
								   AuthenticationRequest authn,
								   ServiceProviderMetadata sp,
								   Assertion assertion) {
		return getSamlDefaults().response(authn, assertion, sp, local);
	}

}
