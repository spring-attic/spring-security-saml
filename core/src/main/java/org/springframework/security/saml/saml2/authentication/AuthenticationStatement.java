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

package org.springframework.security.saml.saml2.authentication;

import org.joda.time.DateTime;

/**
 * Implementation saml:AuthnStatementType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 27, Line 1137
 */
public class AuthenticationStatement {

	private DateTime authInstant;
	private String sessionIndex;
	private DateTime sessionNotOnOrAfter;
	private AuthenticationContext authenticationContext = new AuthenticationContext();


	public DateTime getAuthInstant() {
		return authInstant;
	}

	public AuthenticationStatement setAuthInstant(DateTime authInstant) {
		this.authInstant = authInstant;
		return this;
	}

	public String getSessionIndex() {
		return sessionIndex;
	}

	public AuthenticationStatement setSessionIndex(String sessionIndex) {
		this.sessionIndex = sessionIndex;
		return this;
	}

	public DateTime getSessionNotOnOrAfter() {
		return sessionNotOnOrAfter;
	}

	public AuthenticationStatement setSessionNotOnOrAfter(DateTime sessionNotOnOrAfter) {
		this.sessionNotOnOrAfter = sessionNotOnOrAfter;
		return this;
	}

	public AuthenticationContext getAuthenticationContext() {
		return authenticationContext;
	}

	public AuthenticationStatement setAuthenticationContext(AuthenticationContext authenticationContext) {
		this.authenticationContext = authenticationContext;
		return this;
	}
}
