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

package org.springframework.security.saml.serviceprovider.web.filters;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.metadata.BindingType;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.serviceprovider.ServiceProviderResolver;
import org.springframework.web.util.UrlPathHelper;

import static org.springframework.util.StringUtils.hasText;

class SamlServiceProviderUtils {

	private final SamlTransformer transformer;
	private final ServiceProviderResolver resolver;
	private final ServiceProviderValidator validator;

	SamlServiceProviderUtils(SamlTransformer transformer,
							 ServiceProviderResolver resolver,
							 ServiceProviderValidator validator) {
		this.transformer = transformer;
		this.resolver = resolver;
		this.validator = validator;
	}


	private SamlTransformer getTransformer() {
		return transformer;
	}

	private ServiceProviderResolver getResolver() {
		return resolver;
	}

	private ServiceProviderValidator getValidator() {
		return validator;
	}

	String getEndpointPath(HttpServletRequest request) {
		return new UrlPathHelper().getPathWithinApplication(request);
	}

	HostedServiceProvider getProvider(HttpServletRequest request) {
		HostedServiceProvider serviceProvider = getResolver().getServiceProvider(request);
		if (serviceProvider == null) {
			throw new SamlProviderNotFoundException("hosted");
		}
		return serviceProvider;
	}

	Saml2Object getSamlRequest(HttpServletRequest request) {
		return parseSamlObject(request, getProvider(request), "SAMLRequest");
	}

	Saml2Object getSamlResponse(HttpServletRequest request) {
		return parseSamlObject(request, getProvider(request), "SAMLResponse");
	}

	Endpoint getPreferredEndpoint(List<Endpoint> endpoints,
								  BindingType preferredBinding,
								  int preferredIndex) {
		if (endpoints == null || endpoints.isEmpty()) {
			return null;
		}
		List<Endpoint> eps = endpoints;
		Endpoint result = null;
		//find the preferred binding
		if (preferredBinding != null) {
			for (Endpoint e : eps) {
				if (preferredBinding == e.getBinding().getType()) {
					result = e;
					break;
				}
			}
		}
		//find the configured index
		if (result == null) {
			for (Endpoint e : eps) {
				if (e.getIndex() == preferredIndex) {
					result = e;
					break;
				}
			}
		}
		//find the default endpoint
		if (result == null) {
			for (Endpoint e : eps) {
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

	Saml2Object parseSamlObject(HttpServletRequest request,
								HostedServiceProvider provider,
								String parameterName) {
		Saml2Object result = null;
		String rs = request.getParameter(parameterName);
		if (hasText(rs)) {
			String xml = getTransformer().samlDecode(rs, HttpMethod.GET.matches(request.getMethod()));
			result = getTransformer().fromXml(xml, null, provider.getConfiguration().getKeys());
			if (result instanceof SignableSaml2Object) {
				SignableSaml2Object signableSaml2Object = (SignableSaml2Object) result;
				IdentityProviderMetadata idp = provider.getRemoteProvider(signableSaml2Object.getOriginEntityId());
				if (idp == null) {
					throw new SamlProviderNotFoundException(result.getOriginEntityId());
				}
				try {
					Signature signature =
						getValidator().validateSignature(signableSaml2Object, idp.getIdentityProvider().getKeys());
					signableSaml2Object.setSignature(signature);
				} catch (SignatureException e) {
				}
			}
		}
		return result;
	}

}
