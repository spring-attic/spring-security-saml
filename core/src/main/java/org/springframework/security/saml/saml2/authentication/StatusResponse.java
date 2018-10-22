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

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.ImplementationHolder;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.saml2.signature.Signature;

import org.joda.time.DateTime;

/**
 * Base class for responses samlp:StatusResponseType as defined by
 */
public class StatusResponse<T extends StatusResponse> extends ImplementationHolder {

	private String id;
	private String inResponseTo;
	private String version;
	private DateTime issueInstant;
	private String destination;
	private String consent;
	private Issuer issuer;
	private Signature signature;
	private Status status;
	private SimpleKey signingKey;
	private AlgorithmMethod algorithm;
	private DigestMethod digest;

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

	public Issuer getIssuer() {
		return issuer;
	}

	public T setIssuer(Issuer issuer) {
		this.issuer = issuer;
		return _this();
	}

	public Signature getSignature() {
		return signature;
	}

	public T setSignature(Signature signature) {
		this.signature = signature;
		return _this();
	}

	public Status getStatus() {
		return status;
	}

	public T setStatus(Status status) {
		this.status = status;
		return _this();
	}

	public SimpleKey getSigningKey() {
		return signingKey;
	}

	public AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

	public DigestMethod getDigest() {
		return digest;
	}

	public T setSigningKey(SimpleKey signingKey, AlgorithmMethod algorithm, DigestMethod digest) {
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
