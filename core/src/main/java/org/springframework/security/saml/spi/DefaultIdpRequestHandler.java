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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

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
	protected ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException {

		IdentityProviderMetadata local = getResolver().getLocalIdentityProvider(getNetwork().getBasePath(request));
		String resp = request.getParameter("SAMLRequest");
		//receive assertion
		String xml = getTransformer().samlDecode(resp, GET.matches(request.getMethod()));
		//extract basic data so we can map it to an IDP
		List<SimpleKey> localKeys = local.getIdentityProvider().getKeys();
		AuthenticationRequest authn = (AuthenticationRequest) getTransformer().fromXml(xml, null, localKeys);
		ServiceProviderMetadata sp = getResolver().resolveServiceProvider(authn);
		//validate signature
		authn = (AuthenticationRequest) getTransformer().fromXml(xml, sp.getServiceProvider().getKeys(),localKeys);
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

		String encoded = getTransformer().samlEncode(getTransformer().toXml(result), false);
		String destination = authn.getAssertionConsumerService().getLocation();

		Map<String, String> model = new HashMap<>();
		model.put("action", destination);
		model.put("SAMLResponse", encoded);
		processHtml(request, response, getPostBindingTemplate(), model);
		return ProcessingStatus.STOP;
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		LocalIdentityProviderConfiguration idp = getConfiguration().getIdentityProvider();
		String prefix = idp.getPrefix();
		String path = prefix + "/SSO";
		return isUrlMatch(request, path) && request.getParameter("SAMLRequest") != null;
	}


	protected Response getResponse(IdentityProviderMetadata local,
								   AuthenticationRequest authn,
								   ServiceProviderMetadata sp,
								   Assertion assertion) {
		return getDefaults().response(authn, assertion, sp, local);
	}

}
