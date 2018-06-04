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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class DefaultAuthnRequestHandler extends SamlMessageHandler<DefaultAuthnRequestHandler> {


	@Override
	protected ProcessingStatus process(HttpServletRequest request,
									   HttpServletResponse response) throws IOException {
		ServiceProviderMetadata local = getResolver().getLocalServiceProvider(getNetwork().getBasePath(request));
		IdentityProviderMetadata idp = getResolver().resolveIdentityProvider(request.getParameter("idp"));
		AuthenticationRequest authenticationRequest = getAuthenticationRequest(local, idp);
		String url = getAuthnRequestRedirect(idp, authenticationRequest);
		response.sendRedirect(url);
		return ProcessingStatus.STOP;
	}

	protected AuthenticationRequest getAuthenticationRequest(ServiceProviderMetadata local,
															 IdentityProviderMetadata idp) {
		return getDefaults().authenticationRequest(local, idp);
	}

	protected String getAuthnRequestRedirect(
		IdentityProviderMetadata m,
		AuthenticationRequest authenticationRequest
	) throws
	  UnsupportedEncodingException {
		String encoded = getEncodedAuthnRequestValue(authenticationRequest);
		Endpoint endpoint = m.getIdentityProvider().getSingleSignOnService().get(0);
		UriComponentsBuilder url = UriComponentsBuilder.fromUriString(endpoint.getLocation());
		url.queryParam("SAMLRequest", encoded);
		return url.build(true).toUriString();
	}

	protected String getEncodedAuthnRequestValue(AuthenticationRequest authenticationRequest)
		throws UnsupportedEncodingException {
		String xml = getTransformer().toXml(authenticationRequest);
		String deflated = getTransformer().samlEncode(xml, true);
		return UriUtils.encode(deflated, StandardCharsets.UTF_8.name());
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		LocalServiceProviderConfiguration sp = getConfiguration().getServiceProvider();
		String prefix = sp.getPrefix();
		String path = prefix + "/discovery";
		return isUrlMatch(request, path) && request.getParameter("idp") != null;
	}


}
