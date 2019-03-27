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
package org.springframework.security.saml2.model.authentication;

import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.Saml2ImplementationHolder;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;
import org.springframework.security.saml2.model.signature.Saml2Signature;

import org.joda.time.DateTime;

/**
 * Base class for responses samlp:StatusResponseType as defined by
 */
public class Saml2StatusResponse<T extends Saml2StatusResponse> extends Saml2ImplementationHolder {

	private String id;
	private String inResponseTo;
	private String version;
	private DateTime issueInstant;
	private String destination;
	private String consent;
	private Saml2Issuer issuer;
	private Saml2Signature signature;
	private Saml2Status status;
	private Saml2KeyData signingKey;
	private Saml2AlgorithmMethod algorithm;
	private Saml2DigestMethod digest;

	public String getId() {
		return id;
	}

	public T setId(String id) {
		this.id = id;
		return _this();
	}

	@SuppressWarnings("checked")
	protected T _this() {
		return (T) this;
	}

	public String getInResponseTo() {
		return inResponseTo;
	}

	public T setInResponseTo(String inResponseTo) {
		this.inResponseTo = inResponseTo;
		return _this();
	}

	public String getVersion() {
		return version;
	}

	public T setVersion(String version) {
		this.version = version;
		return _this();
	}

	public DateTime getIssueInstant() {
		return issueInstant;
	}

	public T setIssueInstant(DateTime issueInstant) {
		this.issueInstant = issueInstant;
		return _this();
	}

	public String getDestination() {
		return destination;
	}

	public T setDestination(String destination) {
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

	public Saml2Issuer getIssuer() {
		return issuer;
	}

	public T setIssuer(Saml2Issuer issuer) {
		this.issuer = issuer;
		return _this();
	}

	public Saml2Signature getSignature() {
		return signature;
	}

	public T setSignature(Saml2Signature signature) {
		this.signature = signature;
		return _this();
	}

	public Saml2Status getStatus() {
		return status;
	}

	public T setStatus(Saml2Status status) {
		this.status = status;
		return _this();
	}

	public Saml2KeyData getSigningKey() {
		return signingKey;
	}

	public Saml2AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

	public Saml2DigestMethod getDigest() {
		return digest;
	}

	public T setSigningKey(Saml2KeyData signingKey, Saml2AlgorithmMethod algorithm, Saml2DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
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
		return destination;
	}
}
