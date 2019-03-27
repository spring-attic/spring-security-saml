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
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;

/**
 * Implementation samlp:AuthnRequestType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 50, Line 2147
 */
public class Saml2AuthenticationSaml2Request extends Saml2Request<Saml2AuthenticationSaml2Request>
	implements Saml2SignableObject<Saml2AuthenticationSaml2Request> {

	private String providerName;
	private Saml2Binding binding;
	private Boolean forceAuth;
	private Boolean isPassive;
	private Saml2Endpoint assertionConsumerService;
	private Saml2RequestedAuthenticationContext requestedAuthenticationContext;
	private Saml2AuthenticationContextClassReference authenticationContextClassReference;
	private Saml2KeyData signingKey;
	private Saml2AlgorithmMethod algorithm;
	private Saml2DigestMethod digest;

	private Saml2NameIdPolicy nameIdPolicy;

	public String getProviderName() {
		return providerName;
	}

	public Saml2AuthenticationSaml2Request setProviderName(String providerName) {
		this.providerName = providerName;
		return _this();
	}

	public Saml2Binding getBinding() {
		return binding;
	}

	public Saml2AuthenticationSaml2Request setBinding(Saml2Binding binding) {
		this.binding = binding;
		return _this();
	}

	public Saml2Endpoint getAssertionConsumerService() {
		return assertionConsumerService;
	}

	public Saml2AuthenticationSaml2Request setAssertionConsumerService(Saml2Endpoint assertionConsumerService) {
		this.assertionConsumerService = assertionConsumerService;
		return _this();
	}

	public Saml2RequestedAuthenticationContext getRequestedAuthenticationContext() {
		return requestedAuthenticationContext;
	}

	public Saml2AuthenticationSaml2Request setRequestedAuthenticationContext(
		Saml2RequestedAuthenticationContext requestedAuthenticationContext
	) {
		this.requestedAuthenticationContext = requestedAuthenticationContext;
		return _this();
	}

	public Saml2AuthenticationContextClassReference getAuthenticationContextClassReference() {
		return authenticationContextClassReference;
	}

	public Saml2AuthenticationSaml2Request setAuthenticationContextClassReference(
		Saml2AuthenticationContextClassReference authenticationContextClassReference
	) {
		this.authenticationContextClassReference = authenticationContextClassReference;
		return _this();
	}

	@Override
	public Saml2KeyData getSigningKey() {
		return signingKey;
	}

	@Override
	public Saml2AlgorithmMethod getAlgorithm() {
		return algorithm;
	}

	@Override
	public Saml2DigestMethod getDigest() {
		return digest;
	}

	public Saml2NameIdPolicy getNameIdPolicy() {
		return nameIdPolicy;
	}

	public Saml2AuthenticationSaml2Request setNameIdPolicy(Saml2NameIdPolicy nameIdPolicy) {
		this.nameIdPolicy = nameIdPolicy;
		return _this();
	}

	public Saml2AuthenticationSaml2Request setForceAuth(Boolean forceAuth) {
		this.forceAuth = forceAuth;
		return _this();
	}

	public Saml2AuthenticationSaml2Request setPassive(Boolean passive) {
		isPassive = passive;
		return _this();
	}

	public Boolean isForceAuth() {
		return forceAuth;
	}

	public Boolean isPassive() {
		return isPassive;
	}

	@Override
	public Saml2AuthenticationSaml2Request setSigningKey(Saml2KeyData signingKey, Saml2AlgorithmMethod algorithm, Saml2DigestMethod digest) {
		this.signingKey = signingKey;
		this.algorithm = algorithm;
		this.digest = digest;
		return _this();
	}
}
