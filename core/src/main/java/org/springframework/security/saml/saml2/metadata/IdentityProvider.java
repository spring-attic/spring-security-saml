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
package org.springframework.security.saml.saml2.metadata;

import java.util.List;

import org.springframework.security.saml.saml2.attribute.Attribute;

/**
 * Defines md:IDPSSODescriptorType as defined by
 * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
 * Page 19, Line 792
 */
public class IdentityProvider extends SsoProvider<IdentityProvider> {

	private boolean wantAuthnRequestsSigned = true;
	private List<Endpoint> singleSignOnService;
	private List<Endpoint> nameIDMappingService;
	private List<Endpoint> assertionIDRequestService;
	private List<String> attributeProfile;
	private List<Attribute> attribute;

	public boolean getWantAuthnRequestsSigned() {
		return wantAuthnRequestsSigned;
	}

	public IdentityProvider setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
		this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
		return this;
	}

	public List<Endpoint> getSingleSignOnService() {
		return singleSignOnService;
	}

	public IdentityProvider setSingleSignOnService(List<Endpoint> singleSignOnService) {
		this.singleSignOnService = singleSignOnService;
		return this;
	}

	public List<Endpoint> getNameIDMappingService() {
		return nameIDMappingService;
	}

	public IdentityProvider setNameIDMappingService(List<Endpoint> nameIDMappingService) {
		this.nameIDMappingService = nameIDMappingService;
		return this;
	}

	public List<Endpoint> getAssertionIDRequestService() {
		return assertionIDRequestService;
	}

	public IdentityProvider setAssertionIDRequestService(List<Endpoint> assertionIDRequestService) {
		this.assertionIDRequestService = assertionIDRequestService;
		return this;
	}

	public List<String> getAttributeProfile() {
		return attributeProfile;
	}

	public IdentityProvider setAttributeProfile(List<String> attributeProfile) {
		this.attributeProfile = attributeProfile;
		return this;
	}

	public List<Attribute> getAttribute() {
		return attribute;
	}

	public IdentityProvider setAttribute(List<Attribute> attribute) {
		this.attribute = attribute;
		return this;
	}
}
