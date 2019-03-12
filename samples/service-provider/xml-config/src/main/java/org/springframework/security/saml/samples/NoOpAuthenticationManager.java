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

package org.springframework.security.saml.samples;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * Used with XML configuration where a
 * Spring Security filter chain requires an authentication manager to
 * be configured.
 */
public final class NoOpAuthenticationManager implements AuthenticationManager {
	@Override
	public final Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Assert.notNull(authentication, "Authentication object must not be null");
		if (authentication.isAuthenticated()) {
			return authentication;
		}
		else {
			throw new InsufficientAuthenticationException("Authentication.isAuthenticated must return true");
		}
	}
}
