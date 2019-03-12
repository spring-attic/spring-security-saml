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
package org.springframework.security.saml.saml2.signature;

import org.springframework.security.saml.saml2.key.KeyData;

public class Signature {

	private CanonicalizationMethod canonicalizationAlgorithm;
	private AlgorithmMethod signatureAlgorithm;
	private DigestMethod digestAlgorithm;
	private String digestValue;
	private String signatureValue;
	private boolean validated = false;
	private KeyData validatingKey;

	public CanonicalizationMethod getCanonicalizationAlgorithm() {
		return canonicalizationAlgorithm;
	}

	public Signature setCanonicalizationAlgorithm(CanonicalizationMethod canonicalizationAlgorithm) {
		this.canonicalizationAlgorithm = canonicalizationAlgorithm;
		return this;
	}

	public AlgorithmMethod getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public Signature setSignatureAlgorithm(AlgorithmMethod signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
		return this;
	}

	public DigestMethod getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public Signature setDigestAlgorithm(DigestMethod digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		return this;
	}

	public String getDigestValue() {
		return digestValue;
	}

	public Signature setDigestValue(String digestValue) {
		this.digestValue = digestValue;
		return this;
	}

	public String getSignatureValue() {
		return signatureValue;
	}

	public Signature setSignatureValue(String signatureValue) {
		this.signatureValue = signatureValue;
		return this;
	}

	public boolean isValidated() {
		return validated;
	}

	public Signature setValidated(boolean b) {
		this.validated = b;
		return this;
	}

	public KeyData getValidatingKey() {
		return validatingKey;
	}

	public Signature setValidatingKey(KeyData validatingKey) {
		this.validatingKey = validatingKey;
		return this;
	}
}
