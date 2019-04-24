/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.saml2.serviceprovider.servlet.util;

import java.util.List;

import org.springframework.security.saml2.Saml2ProviderNotFoundException;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.metadata.Saml2BindingType;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.provider.Saml2ServiceProviderInstance;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public final class Saml2ServiceProviderUtils {

	public static Saml2Endpoint getPreferredEndpoint(List<Saml2Endpoint> endpoints,
													 Saml2BindingType preferredBinding,
													 int preferredIndex) {
		if (endpoints == null || endpoints.isEmpty()) {
			return null;
		}
		List<Saml2Endpoint> eps = endpoints;
		Saml2Endpoint result = null;
		//find the preferred binding
		if (preferredBinding != null) {
			for (Saml2Endpoint e : eps) {
				if (preferredBinding == e.getBinding().getType()) {
					result = e;
					break;
				}
			}
		}
		//find the configured index
		if (result == null) {
			for (Saml2Endpoint e : eps) {
				if (e.getIndex() == preferredIndex) {
					result = e;
					break;
				}
			}
		}
		//find the default endpoint
		if (result == null) {
			for (Saml2Endpoint e : eps) {
				if (e.isDefault()) {
					result = e;
					break;
				}
			}
		}
		//fallback to the very first available endpoint
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}

	/**
	 * Decodes and constructs a Saml2Object from an encoded string.
	 * @param encodedSamlObject - SAML 2 Object in encoded format
	 * @param inflate - set to true if the encoding has been deflated
	 * @param provider - the server provider this object is intended for. provider keys are used in case object is encrypted
	 * @param transformer - the transformer to transform the object from string to {@link Saml2Object}
	 * @param validator - if not null, signature and object validation will be attempted. may be null.
	 * @return the decoded, and possibly validated, SAML2 object
	 * @throws {@link Saml2ProviderNotFoundException} if the origin of the message is not found in the service provider instance
	 * @throws {@link org.springframework.security.saml2.model.signature.Saml2SignatureException} if signature validation fails
	 * @throws {@link org.springframework.security.saml2.Saml2Exception} if decoding fails
	 */
	public static Saml2Object parseSaml2Object(String encodedSamlObject,
											   boolean inflate,
											   Saml2ServiceProviderInstance provider,
											   Saml2Transformer transformer,
											   Saml2ServiceProviderValidator validator) {
		Saml2Object result = null;
		if (!hasText(encodedSamlObject)) {
			return result;
		}
		String xml = transformer.samlDecode(encodedSamlObject, inflate);
		result = transformer.fromXml(xml, null, provider.getRegistration().getKeys());
		if (result instanceof Saml2SignableObject && ofNullable(validator).isPresent()) {
			Saml2SignableObject signableSaml2Object = (Saml2SignableObject) result;
			Saml2IdentityProviderMetadata idp = provider.getRemoteProvider(signableSaml2Object.getOriginEntityId());
			if (idp == null) {
				throw new Saml2ProviderNotFoundException(result.getOriginEntityId());
			}
			Saml2Signature signature = validator.validateSignature(
				signableSaml2Object,
				idp.getIdentityProvider().getKeys()
			);
			signableSaml2Object.setSignature(signature);
		}
		return result;
	}

}
