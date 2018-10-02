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

package org.springframework.security.saml.provider.service;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.HostedProviderService;
import org.springframework.security.saml.provider.config.HostedProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SamlRequestMatcherTests {

	private SamlProviderProvisioning provisioning = mock(SamlProviderProvisioning.class);
	private HostedProviderConfiguration configuration = mock(HostedProviderConfiguration.class);
	private HostedProviderService provider = mock(HostedProviderService.class);
	private String prefix;
	private String url;
	private SamlRequestMatcher matcher;
	private String path;
	private String alias;
	private String servletPath = "";
	private String contextPath = "";
	private MockHttpServletRequest request;

	@BeforeEach
	void setUp() {
		alias = "some-alias";
		path = "SSO";
		prefix = "/saml/sp";
		url = "/saml/sp/SSO/alias/some-alias";


		when(configuration.getPrefix()).then(invocation -> getPath());
		when(configuration.getAlias()).then(invocation -> getAlias());
		when(configuration.getPrefix()).then(invocation -> getPrefix());
		when(provider.getConfiguration()).thenReturn(configuration);
		when(provisioning.getHostedProvider()).thenReturn(provider);
	}

	private String getPath() {
		return path;
	}

	public String getAlias() {
		return alias;
	}

	private String getPrefix() {
		return prefix;
	}

	@Test
	public void contextMatch() {
		contextPath = "/myapp";
		match();
	}

	@Test
	public void match() {
		matcher = new SamlRequestMatcher(getProvisioning(), getPath());
		request = getRequest();
		assertTrue(matches(request));
	}

	private SamlProviderProvisioning getProvisioning() {
		return provisioning;
	}

	protected MockHttpServletRequest getRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.POST.name(), url);
		request.setPathInfo(getUrl());
		request.setServletPath(getServletPath());
		request.setContextPath(getContextPath());
		return request;
	}

	private boolean matches(MockHttpServletRequest request) {
		return matcher.matches(request);
	}

	private String getUrl() {
		return url;
	}

	private String getServletPath() {
		return servletPath;
	}

	private String getContextPath() {
		return contextPath;
	}

	@Test
	public void misMatch() {
		path = "logout";
		matcher = new SamlRequestMatcher(getProvisioning(), getPath());
		request = getRequest();
		assertFalse(matches(request));
	}

	@Test
	public void aliasMatch() {
		matcher = new SamlRequestMatcher(getProvisioning(), getPath(), true);
		request = getRequest();
		assertTrue(matches(request));
	}

	@Test
	public void aliasMisMatch() {
		matcher = new SamlRequestMatcher(getProvisioning(), getPath(), true);
		url = "/saml/sp/SSO/alias/some-other-alias";
		request = getRequest();
		assertFalse(matches(request));
	}

	@Test
	public void aliasIgnored() {
		url = "/saml/sp/SSO/alias/some-other-alias";
		matcher = new SamlRequestMatcher(getProvisioning(), getPath());
		request = getRequest();
		assertTrue(matches(request));
	}

}