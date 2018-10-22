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

package org.springframework.security.saml.saml2.authentication;

import java.util.List;

import org.springframework.security.saml.saml2.ImplementationHolder;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.signature.Signature;

import org.joda.time.DateTime;

/**
 * Base class for requests
 *
 * @param <T> - subclass to be returned as part of Builder pattern
 */
public class Request<T extends Request<T>> extends ImplementationHolder {

	private Issuer issuer;
	private Signature signature;
	private List<Object> extensions;
	private String id;
	private DateTime issueInstant;
	private Endpoint destination;
	private String consent;
	private String version = "2.0";

	public Issuer getIssuer() {
		return issuer;
	}

	public T setIssuer(Issuer issuer) {
		this.issuer = issuer;
		return _this();
	}

	protected T _this() {
		return (T) this;
	}

	public Signature getSignature() {
		return signature;
	}

	public T setSignature(Signature signature) {
		this.signature = signature;
		return _this();
	}

	public List<Object> getExtensions() {
		return extensions;
	}

	public T setExtensions(List<Object> extensions) {
		this.extensions = extensions;
		return _this();
	}

	public String getId() {
		return id;
	}

	public T setId(String id) {
		this.id = id;
		return _this();
	}

	public DateTime getIssueInstant() {
		return issueInstant;
	}

	public T setIssueInstant(DateTime issueInstant) {
		this.issueInstant = issueInstant;
		return _this();
	}

	public Endpoint getDestination() {
		return destination;
	}

	public T setDestination(Endpoint destination) {
		this.destination = destination;
		return _this();
	}

	public String getConsent() {
		return consent;
	}

	public T setConsent(String consent) {
		this.consent = consent;
		return _this();
	}

	public String getVersion() {
		return version;
	}

	public T setVersion(String version) {
		this.version = version;
		return _this();
	}

	@Override
	public String getOriginEntityId() {
		if (issuer != null) {
			return issuer.getValue();
		}
		return null;
	}

	@Override
	public String getDestinationEntityId() {
		return null;
	}
}
