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
package org.springframework.security.saml.saml2.metadata;

import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.saml2.attribute.Attribute;

/**
 * Defines md:SPSSODescriptorType as defined by
 * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
 * Page 20, Line 846
 */
public class ServiceProvider extends SsoProvider<ServiceProvider> {

	private boolean authnRequestsSigned;
	private boolean wantAssertionsSigned;
	private List<Endpoint> assertionConsumerService = new LinkedList<>();
	private Endpoint configuredAssertionConsumerService;
	private List<Attribute> requestedAttributes = new LinkedList<>();

	//private List<AttributeConsumingService> attributeConsumingService;

	public boolean getAuthnRequestsSigned() {
		return authnRequestsSigned;
	}

	public boolean getWantAssertionsSigned() {
		return wantAssertionsSigned;
	}

	public List<Endpoint> getAssertionConsumerService() {
		return assertionConsumerService;
	}

//    public List<Endpoint> getAttributeConsumingService() {
//        return attributeConsumingService;
//    }

	public ServiceProvider setAssertionConsumerService(List<Endpoint> assertionConsumerService) {
		this.assertionConsumerService = assertionConsumerService;
		return _this();
	}

	public boolean isAuthnRequestsSigned() {
		return authnRequestsSigned;
	}

	public ServiceProvider setAuthnRequestsSigned(boolean authnRequestsSigned) {
		this.authnRequestsSigned = authnRequestsSigned;
		return _this();
	}

	public boolean isWantAssertionsSigned() {
		return wantAssertionsSigned;
	}

	public ServiceProvider setWantAssertionsSigned(boolean wantAssertionsSigned) {
		this.wantAssertionsSigned = wantAssertionsSigned;
		return _this();
	}

	public Endpoint getConfiguredAssertionConsumerService() {
		return configuredAssertionConsumerService;
	}

	public ServiceProvider setConfiguredAssertionConsumerService(
		Endpoint
			configuredAssertionConsumerService
	) {
		this.configuredAssertionConsumerService = configuredAssertionConsumerService;
		return _this();
	}

	public List<Attribute> getRequestedAttributes() {
		return requestedAttributes;
	}

	public ServiceProvider setRequestedAttributes(List<Attribute> requestedAttributes) {
		this.requestedAttributes = requestedAttributes;
		return this;
	}
}
