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

package org.springframework.security.saml.spi;

import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;

import static java.nio.charset.StandardCharsets.UTF_8;

public abstract class DefaultSamlTransformer implements SamlTransformer, InitializingBean {

	private SpringSecuritySaml implementation;

	public DefaultSamlTransformer(SpringSecuritySaml implementation) {
		setImplementation(implementation);
	}

	public SamlTransformer setImplementation(SpringSecuritySaml implementation) {
		this.implementation = implementation;
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void afterPropertiesSet() {
		implementation.init();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toXml(Saml2Object saml2Object) {
		return implementation.toXml(saml2Object);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2Object fromXml(byte[] xml, List<KeyData> verificationKeys, List<KeyData> localKeys) {
		return implementation.resolve(xml, verificationKeys, localKeys);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String samlEncode(String s, boolean deflate) {
		byte[] b;
		if (deflate) {
			b = implementation.deflate(s);
		}
		else {
			b = s.getBytes(UTF_8);
		}
		return implementation.encode(b);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String samlDecode(String s, boolean inflate) {
		byte[] b = implementation.decode(s);
		if (inflate) {
			return implementation.inflate(b);
		}
		else {
			return new String(b, UTF_8);
		}
	}

	@Override
	public Signature validateSignature(SignableSaml2Object saml2Object, List<KeyData> trustedKeys)
		throws SignatureException {
		if (saml2Object == null || saml2Object.getImplementation() == null) {
			throw new SignatureException("No object to validate signature against.");
		}

		if (saml2Object instanceof Assertion && ((Assertion) saml2Object).isEncrypted()) {
			//we don't need to validate the signature
			//of an assertion that was successfully decrypted
			try {
				return implementation.getValidSignature(saml2Object, trustedKeys);
			} catch (SignatureException x) {
				//ignore. if we decrypted the object, we don't need this
				return null;
			}
		}

		if (trustedKeys == null || trustedKeys.isEmpty()) {
			throw new SignatureException("At least one verification key has to be provided");
		}

		return implementation.getValidSignature(saml2Object, trustedKeys);
	}

}
