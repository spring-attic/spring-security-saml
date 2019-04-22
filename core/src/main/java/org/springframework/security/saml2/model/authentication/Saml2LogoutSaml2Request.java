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

import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;

import org.joda.time.DateTime;

/**
 * Implementation samlp:LogoutRequestType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 62, Line 2686
 */
public class Saml2LogoutSaml2Request extends Saml2Request<Saml2LogoutSaml2Request>
	implements Saml2SignableObject<Saml2LogoutSaml2Request> {

	private Saml2KeyData signingKey;
	private Saml2AlgorithmMethod algorithm;
	private Saml2DigestMethod digest;
	private Saml2NameIdPrincipal nameId;
	private Saml2LogoutReason reason;
	private DateTime notOnOrAfter;

	public Saml2AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

	public Saml2LogoutSaml2Request setAlgorithm(Saml2AlgorithmMethod algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	public Saml2DigestMethod getDigest() {
		return digest;
	}

	public Saml2LogoutSaml2Request setDigest(Saml2DigestMethod digest) {
		this.digest = digest;
		return this;
	}

	public Saml2NameIdPrincipal getNameId() {
		return nameId;
	}

	public Saml2LogoutSaml2Request setNameId(Saml2NameIdPrincipal nameId) {
		this.nameId = nameId;
		return this;
	}

	public Saml2LogoutReason getReason() {
		return reason;
	}

	public Saml2LogoutSaml2Request setReason(Saml2LogoutReason reason) {
		this.reason = reason;
		return this;
	}

	public DateTime getNotOnOrAfter() {
		return notOnOrAfter;
	}

	public Saml2LogoutSaml2Request setNotOnOrAfter(DateTime notOnOrAfter) {
		this.notOnOrAfter = notOnOrAfter;
		return this;
	}

	public Saml2KeyData getSigningKey() {
		return signingKey;
	}

	public Saml2LogoutSaml2Request setSigningKey(Saml2KeyData signingKey, Saml2AlgorithmMethod algorithm, Saml2DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return _this();
	}
}
