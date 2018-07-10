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

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultLogoutHandlerTests {

	LocalIdentityProviderConfiguration idp;
	DefaultLogoutHandler handler;
	MockHttpServletRequest request;

	@BeforeEach
	public void setup() {
		idp = new LocalIdentityProviderConfiguration()
			.setPrefix("")
			.setAlias("idp-alias");
		handler = new DefaultLogoutHandler();
		request = new MockHttpServletRequest();
		request.setPathInfo("/logout/alias/idp-alias");
	}

	@Test
	public void singleLogoutEnabled() {
		request.setPathInfo("/logout");
		assertTrue(handler.internalSupports(request, idp));
	}

	@Test
	public void singleLogoutEnabledAliasEnabled() {
		request.setPathInfo("/logout");
		handler.setMatchAgainstAliasPath(true);
		assertFalse(handler.internalSupports(request, idp));
	}

	@Test
	public void singleLogoutEnabledWithAlias() {
		request.setPathInfo("/logout/alias/idp-alias");
		assertTrue(handler.internalSupports(request, idp));
	}

	@Test
	public void singleLogoutDisabled() {
		idp.setSingleLogoutEnabled(false);
		assertFalse(handler.internalSupports(request, idp));
	}

}