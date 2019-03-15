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

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import org.joda.time.DateTime;

/**
 * Implementation samlp:LogoutRequestType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 62, Line 2686
 */
public class LogoutRequest extends Request<LogoutRequest> {

	private SimpleKey signingKey;
	private AlgorithmMethod algorithm;
	private DigestMethod digest;
	private NameIdPrincipal nameId;
	private LogoutReason reason;
	private DateTime notOnOrAfter;

	public AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

	public LogoutRequest setAlgorithm(AlgorithmMethod algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	public DigestMethod getDigest() {
		return digest;
	}

	public LogoutRequest setDigest(DigestMethod digest) {
		this.digest = digest;
		return this;
	}

	public NameIdPrincipal getNameId() {
		return nameId;
	}

	public LogoutRequest setNameId(NameIdPrincipal nameId) {
		this.nameId = nameId;
		return this;
	}

	public LogoutReason getReason() {
		return reason;
	}

	public LogoutRequest setReason(LogoutReason reason) {
		this.reason = reason;
		return this;
	}

	public DateTime getNotOnOrAfter() {
		return notOnOrAfter;
	}

	public LogoutRequest setNotOnOrAfter(DateTime notOnOrAfter) {
		this.notOnOrAfter = notOnOrAfter;
		return this;
	}

	public SimpleKey getSigningKey() {
		return signingKey;
	}

	public LogoutRequest setSigningKey(SimpleKey signingKey, AlgorithmMethod algorithm, DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return _this();
	}
}
