/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml2.serviceprovider.servlet.util;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml2.Saml2ProviderNotFoundException;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.metadata.Saml2BindingType;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;
import org.springframework.security.saml2.provider.HostedSaml2ServiceProvider;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderResolver;

import static org.springframework.util.StringUtils.hasText;

public class DefaultSaml2ServiceProviderMethods implements Saml2ServiceProviderMethods {

	private final Saml2Transformer transformer;
	private final Saml2ServiceProviderResolver resolver;
	private final Saml2ServiceProviderValidator validator;

	public DefaultSaml2ServiceProviderMethods(Saml2Transformer transformer,
											  Saml2ServiceProviderResolver resolver,
											  Saml2ServiceProviderValidator validator) {
		this.transformer = transformer;
		this.resolver = resolver;
		this.validator = validator;
	}

	@Override
	public Saml2Object getSamlRequest(HttpServletRequest request) {
		return parseSamlObject(request, getProvider(request), "SAMLRequest");
	}

	@Override
	public Saml2Object parseSamlObject(HttpServletRequest request,
									   HostedSaml2ServiceProvider provider,
									   String parameterName) {
		Saml2Object result = null;
		String rs = request.getParameter(parameterName);
		if (hasText(rs)) {
			String xml = getTransformer().samlDecode(rs, HttpMethod.GET.matches(request.getMethod()));
			result = getTransformer().fromXml(xml, null, provider.getConfiguration().getKeys());
			if (result instanceof Saml2SignableObject) {
				Saml2SignableObject signableSaml2Object = (Saml2SignableObject) result;
				Saml2IdentityProviderMetadata idp = provider.getRemoteProvider(signableSaml2Object.getOriginEntityId());
				if (idp == null) {
					throw new Saml2ProviderNotFoundException(result.getOriginEntityId());
				}
				try {
					Saml2Signature signature =
						getValidator().validateSignature(signableSaml2Object, idp.getIdentityProvider().getKeys());
					signableSaml2Object.setSignature(signature);
				} catch (Saml2SignatureException e) {
				}
			}
		}
		return result;
	}

	@Override
	public HostedSaml2ServiceProvider getProvider(HttpServletRequest request) {
		HostedSaml2ServiceProvider serviceProvider = getResolver().getServiceProvider(request);
		if (serviceProvider == null) {
			throw new Saml2ProviderNotFoundException("hosted");
		}
		return serviceProvider;
	}

	@Override
	public Saml2Transformer getTransformer() {
		return transformer;
	}

	@Override
	public Saml2ServiceProviderValidator getValidator() {
		return validator;
	}

	@Override
	public Saml2ServiceProviderResolver getResolver() {
		return resolver;
	}

	@Override
	public Saml2Object getSamlResponse(HttpServletRequest request) {
		return parseSamlObject(request, getProvider(request), "SAMLResponse");
	}

	@Override
	public Saml2Endpoint getPreferredEndpoint(List<Saml2Endpoint> endpoints,
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

}
