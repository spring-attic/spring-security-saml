/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.provider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class SamlProviderLogoutFilter<T extends HostedProviderService> extends LogoutFilter {

	private final SamlProviderProvisioning<T> provisioning;

	public SamlProviderLogoutFilter(SamlProviderProvisioning<T> provisioning,
									LogoutHandler samlLogoutHandler,
									LogoutSuccessHandler logoutSuccessHandler,
									LogoutHandler... handlers) {
		this(
			provisioning,
			samlLogoutHandler,
			new SamlRequestMatcher(provisioning, "logout"),
			logoutSuccessHandler,
			handlers
		);
	}

	public SamlProviderLogoutFilter(SamlProviderProvisioning<T> provisioning,
									LogoutHandler samlLogoutHandler,
									RequestMatcher requestMatcher,
									LogoutSuccessHandler logoutSuccessHandler,
									LogoutHandler... handlers) {
		super(
			new SamlLogoutSuccessHandler(logoutSuccessHandler, handlers),
			samlLogoutHandler
		);
		this.provisioning = provisioning;
		setLogoutRequestMatcher(requestMatcher);
	}

	@Override
	protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
		boolean result = super.requiresLogout(request, response);
		return result;
	}

}
