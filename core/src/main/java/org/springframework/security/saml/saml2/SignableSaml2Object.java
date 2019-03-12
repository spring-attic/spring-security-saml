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

package org.springframework.security.saml.saml2;

import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.saml2.signature.Signature;

public interface SignableSaml2Object<T extends Saml2Object> extends Saml2Object {

	T setSigningKey(KeyData signingKey, AlgorithmMethod algorithm, DigestMethod digest);

	KeyData getSigningKey();

	AlgorithmMethod getAlgorithm();

	DigestMethod getDigest();

	String getId();

	T setSignature(Signature signature);

	Signature getSignature();
}
