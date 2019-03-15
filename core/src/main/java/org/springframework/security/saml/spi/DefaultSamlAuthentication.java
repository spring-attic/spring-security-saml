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

package org.springframework.security.saml.spi;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.SubjectPrincipal;

public class DefaultSamlAuthentication implements SamlAuthentication {
	private boolean authenticated;
	private Assertion assertion;
	private String assertingEntityId;
	private String holdingEntityId;
	private String relayState;
	private String responseXml;

	public DefaultSamlAuthentication(boolean authenticated,
									 Assertion assertion,
									 String assertingEntityId,
									 String holdingEntityId,
									 String relayState) {
		this.authenticated = authenticated;
		this.assertion = assertion;
		this.assertingEntityId = assertingEntityId;
		this.holdingEntityId = holdingEntityId;
		this.relayState = relayState;
	}

	@Override
	public String getAssertingEntityId() {
		return assertingEntityId;
	}

	@Override
	public String getHoldingEntityId() {
		return holdingEntityId;
	}

	@Override
	public SubjectPrincipal<? extends SubjectPrincipal> getSamlPrincipal() {
		return assertion.getSubject().getPrincipal();
	}

	public Assertion getAssertion() {
		return assertion;
	}

	protected void setAssertion(Assertion assertion) {
		this.assertion = assertion;
	}

	@Override
	public String getRelayState() {
		return relayState;
	}

	public void setRelayState(String relayState) {
		this.relayState = relayState;
	}

	protected void setHoldingEntityId(String holdingEntityId) {
		this.holdingEntityId = holdingEntityId;
	}

	protected void setAssertingEntityId(String assertingEntityId) {
		this.assertingEntityId = assertingEntityId;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		return getAssertion();
	}

	@Override
	public Object getPrincipal() {
		return getSamlPrincipal();
	}

	@Override
	public boolean isAuthenticated() {
		return authenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (!authenticated && isAuthenticated) {
			throw new IllegalArgumentException("Unable to change state of an existing authentication object.");
		}
	}

	@Override
	public String getName() {
		return getSamlPrincipal().getValue();
	}

	public String getResponseXml() {
		return responseXml;
	}

	public DefaultSamlAuthentication setResponseXml(String responseXml) {
		this.responseXml = responseXml;
		return this;
	}
}
