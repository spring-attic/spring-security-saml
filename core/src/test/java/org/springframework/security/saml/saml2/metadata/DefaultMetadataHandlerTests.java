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

package org.springframework.security.saml.saml2.metadata;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.spi.DefaultMetadataHandler;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpMethod.GET;

public class DefaultMetadataHandlerTests extends MetadataBase {

	private DefaultMetadataHandler handler;
	private SamlServerConfiguration configuration;

	@BeforeEach
	public void setup() {
		handler = new DefaultMetadataHandler();
		configuration = new SamlServerConfiguration();
		configuration.setIdentityProvider(new LocalIdentityProviderConfiguration());
		configuration.setServiceProvider(new LocalServiceProviderConfiguration());
		handler.setConfiguration(configuration);
	}

	@Test
	public void supportsIdp() throws Exception {

		configuration.setServiceProvider(null);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml/idp/metadata");
		request.setMethod(GET.name());
		assertTrue(handler.supports(request));

		request.setPathInfo("/saml/sp/metadata");
		assertFalse(handler.supports(request));
	}

	@Test
	public void supportsSp() throws Exception {

		configuration.setIdentityProvider(null);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml/sp/metadata");
		request.setMethod(GET.name());
		assertTrue(handler.supports(request));

		request.setPathInfo("/saml/idp/metadata");
		assertFalse(handler.supports(request));
	}
}
