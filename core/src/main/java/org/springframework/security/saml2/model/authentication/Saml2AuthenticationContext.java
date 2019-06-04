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
import java.util.List;

import static org.springframework.security.saml2.model.authentication.Saml2AuthenticationContextClassReference.Saml2AuthenticationContextClassReferenceType.UNSPECIFIED;

public class Saml2AuthenticationContext {

	private Saml2AuthenticationContextClassReference classReference =
		Saml2AuthenticationContextClassReference.fromUrn(UNSPECIFIED);

	private List<String> authenticatingAuthorities = Collections.emptyList();


	public Saml2AuthenticationContextClassReference getClassReference() {
		return classReference;
	}

	public Saml2AuthenticationContext setClassReference(Saml2AuthenticationContextClassReference classReference) {
		this.classReference = classReference;
		return this;
	}

	public List<String> getAuthenticatingAuthorities() {
		return authenticatingAuthorities;
	}

	public Saml2AuthenticationContext setAuthenticatingAuthorities(List<String> authenticatingAuthorities) {
		this.authenticatingAuthorities = authenticatingAuthorities;
		return this;
	}
}
