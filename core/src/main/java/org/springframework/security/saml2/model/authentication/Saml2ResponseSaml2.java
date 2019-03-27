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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;

/**
 * Implementation samlp:ResponseType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 47, Line 1995
 */
public class Saml2ResponseSaml2 extends Saml2StatusResponse<Saml2ResponseSaml2>
	implements Saml2SignableObject<Saml2ResponseSaml2> {
	private List<Saml2Assertion> assertions = new LinkedList<>();

	private Saml2KeyData signingKey = null;
	private Saml2AlgorithmMethod algorithm;
	private Saml2DigestMethod digest;

	public List<Saml2Assertion> getAssertions() {
		return Collections.unmodifiableList(assertions);
	}

	public Saml2ResponseSaml2 setAssertions(List<Saml2Assertion> assertions) {
		this.assertions.clear();
		this.assertions.addAll(assertions);
		return this;
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

	@Override
	public Saml2ResponseSaml2 setSigningKey(Saml2KeyData signingKey,
											Saml2AlgorithmMethod algorithm,
											Saml2DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return this;
	}

	public Saml2ResponseSaml2 addAssertion(Saml2Assertion assertion) {
		this.assertions.add(assertion);
		return this;
	}
}
