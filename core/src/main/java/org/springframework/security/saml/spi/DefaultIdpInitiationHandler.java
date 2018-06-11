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
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

public class DefaultIdpInitiationHandler extends IdpAssertionHandler<DefaultIdpInitiationHandler> {

	private SamlValidator validator;
	private String postBindingTemplate;
	private DefaultSessionAssertionStore store;

	public SamlValidator getValidator() {
		return validator;
	}

	public DefaultIdpInitiationHandler setValidator(SamlValidator validator) {
		this.validator = validator;
		return this;
	}

	public DefaultSessionAssertionStore getStore() {
		return store;
	}

	public DefaultIdpInitiationHandler setStore(DefaultSessionAssertionStore store) {
		this.store = store;
		return this;
	}

	public String getPostBindingTemplate() {
		return postBindingTemplate;
	}

	public DefaultIdpInitiationHandler setPostBindingTemplate(String postBindingTemplate) {
		this.postBindingTemplate = postBindingTemplate;
		return this;
	}

	@Override
	protected ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException {

		String entityId = request.getParameter("sp");
		//no authnrequest provided
		ServiceProviderMetadata metadata = getResolver().resolveServiceProvider(entityId);
		IdentityProviderMetadata local = getResolver().getLocalIdentityProvider(getNetwork().getBasePath
			(request));
		Assertion assertion = getAssertion(
			local,
			null,
			metadata,
			SecurityContextHolder.getContext().getAuthentication(),
			request,
			store
		);
		Response result = getResponse(metadata, local, assertion);
		String encoded = getTransformer().samlEncode(getTransformer().toXml(result), false);
		Map<String, String> model = new HashMap<>();
		model.put("action", getAcs(metadata));
		model.put("SAMLResponse", encoded);
		processHtml(request, response, getPostBindingTemplate(), model);
		return ProcessingStatus.STOP;
	}

	protected Response getResponse(
		ServiceProviderMetadata metadata, IdentityProviderMetadata local,
		Assertion assertion
	) {
		return getDefaults().response(
			null,
			assertion,
			metadata,
			local
		);
	}

	protected String getAcs(ServiceProviderMetadata metadata) {
		List<Endpoint> acs = metadata.getServiceProvider().getAssertionConsumerService();
		Endpoint result = acs.stream().filter(e -> e.isDefault()).findFirst().orElse(null);
		if (result == null) {
			result = acs.get(0);
		}
		return result.getLocation();
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		LocalIdentityProviderConfiguration idp = getConfiguration().getIdentityProvider();
		String prefix = idp.getPrefix();
		String path = prefix + "/init";
		return isUrlMatch(request, path) && request.getParameter("sp") != null;
	}
}
