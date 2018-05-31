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
import org.springframework.security.saml.SamlProcessor;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import static org.springframework.http.HttpMethod.GET;

public class DefaultIdpRequestProcessor extends SamlProcessor<DefaultIdpRequestProcessor> {

	private SamlValidator validator;
	private String postBindingTemplate;

	@Override
	protected void doProcess(HttpServletRequest request,
							 HttpServletResponse response,
							 Saml2Object saml2Object) throws IOException {

		IdentityProviderMetadata local = getResolver().getLocalIdentityProvider(getNetwork().getBasePath(request));
		String resp = request.getParameter("SAMLRequest");
		//receive assertion
		String xml = getTransformer().samlDecode(resp, GET.matches(request.getMethod()));
		//extract basic data so we can map it to an IDP
		List<SimpleKey> localKeys = getResolver()
			.getLocalIdentityProvider(getNetwork().getBasePath(request))
			.getIdentityProvider()
			.getKeys();
		AuthenticationRequest authn = (AuthenticationRequest) getTransformer().fromXml(xml, null, localKeys);
		ServiceProviderMetadata sp = getResolver().resolveServiceProvider(authn);
		//validate signature
		authn = (AuthenticationRequest) getTransformer().fromXml(xml, local.getIdentityProvider().getKeys(), localKeys);
		getValidator().validate(authn, getResolver(), request);
		//create the assertion

		String principal = SecurityContextHolder.getContext().getAuthentication().getName();
		Assertion assertion = getDefaults().assertion(sp, local, authn, principal, NameId.PERSISTENT);

		Response result = getDefaults().response(authn,assertion,sp,local);

		String encoded = getTransformer().samlEncode(getTransformer().toXml(result), false);
		String destination = authn.getAssertionConsumerService().getLocation();

		Map<String,String> model = new HashMap<>();
		model.put("action", destination);
		model.put("SAMLResponse", encoded);
		processHtml(request, response, postBindingTemplate, model);
	}

	@Override
	protected void validate(Saml2Object saml2Object) {
		//no op
	}

	@Override
	protected Saml2Object extract(HttpServletRequest request) {
		//no op
		return null;
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		LocalIdentityProviderConfiguration idp = getConfiguration().getIdentityProvider();
		String prefix = idp.getPrefix();
		String path = prefix + "/SSO";
		return isUrlMatch(request, path) && request.getParameter("SAMLRequest")!=null;
	}


	public SamlValidator getValidator() {
		return validator;
	}

	public DefaultIdpRequestProcessor setValidator(SamlValidator validator) {
		this.validator = validator;
		return this;
	}

	public String getPostBindingTemplate() {
		return postBindingTemplate;
	}

	public DefaultIdpRequestProcessor setPostBindingTemplate(String postBindingTemplate) {
		this.postBindingTemplate = postBindingTemplate;
		return this;
	}
}
