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

package org.springframework.security.saml.saml2.authentication;

import java.util.List;

/**
 * Implementation samlp:RequestedAuthnContext as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 44, Line 1895
 */
public class RequestedAuthenticationContext {

	private Comparison comparison;
	private List<String> authenticationContextClassReferences;
	private List<String> authenticationContextClassDeclarations;

	public Comparison getComparison() {
		return comparison;
	}

	public RequestedAuthenticationContext setComparison(Comparison comparison) {
		this.comparison = comparison;
		return this;
	}

	public List<String> getAuthenticationContextClassReferences() {
		return authenticationContextClassReferences;
	}

	public RequestedAuthenticationContext setAuthenticationContextClassReferences(List<String> authenticationContextClassReferences) {
		this.authenticationContextClassReferences = authenticationContextClassReferences;
		return this;
	}

	public List<String> getAuthenticationContextClassDeclarations() {
		return authenticationContextClassDeclarations;
	}

	public RequestedAuthenticationContext setAuthenticationContextClassDeclarations(List<String> authenticationContextClassDeclarations) {
		this.authenticationContextClassDeclarations = authenticationContextClassDeclarations;
		return this;
	}
}
