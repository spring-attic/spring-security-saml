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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.Metadata;

public class DefaultMetadataHandler extends SamlMessageHandler<DefaultMetadataHandler> {

	protected final String LOCAL_PROVIDER = getClass().getName() + ".local.provider";

	@Override
	protected ProcessingStatus process(HttpServletRequest request,HttpServletResponse response) throws IOException {
		LocalProviderConfiguration provider =
			(LocalProviderConfiguration) request.getAttribute(LOCAL_PROVIDER);
		Metadata metadata = getMetadata(request, provider);
		response.setContentType(MediaType.TEXT_XML_VALUE);
		String xml = getTransformer().toXml(metadata);
		response.getWriter().write(xml);
		return ProcessingStatus.STOP;
	}

	protected Metadata getMetadata(HttpServletRequest request, LocalProviderConfiguration provider) {
		return provider instanceof LocalIdentityProviderConfiguration ?
			getResolver().getLocalIdentityProvider(getNetwork().getBasePath(request)) :
			getResolver().getLocalServiceProvider(getNetwork().getBasePath(request));
	}

	@Override
	public boolean supports(HttpServletRequest request) {
		return
			internalSupports(request, getConfiguration().getIdentityProvider()) ||
				internalSupports(request, getConfiguration().getServiceProvider());
	}

	protected boolean internalSupports(HttpServletRequest request, LocalProviderConfiguration provider) {
		boolean result = false;
		if (provider != null) {
			String prefix = provider.getPrefix();
			String path = prefix + "/metadata";
			if (isUrlMatch(request, path)) {
				result = true;
				request.setAttribute(LOCAL_PROVIDER, provider);
			}
		}
		return result;
	}
}
