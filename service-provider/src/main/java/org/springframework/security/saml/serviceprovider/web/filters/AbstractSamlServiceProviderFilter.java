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

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.serviceprovider.web.ServiceProviderResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.util.StringUtils.hasText;

public abstract class AbstractSamlServiceProviderFilter extends OncePerRequestFilter {


	private final SamlTransformer transformer;
	private final ServiceProviderResolver resolver;
	private final ServiceProviderValidator validator;
	private final RequestMatcher matcher;

	public AbstractSamlServiceProviderFilter(SamlTransformer transformer,
											 ServiceProviderResolver resolver,
											 ServiceProviderValidator validator,
											 RequestMatcher matcher) {
		this.transformer = transformer;
		this.resolver = resolver;
		this.validator = validator;
		this.matcher = matcher;
	}

	protected Saml2Object parseSamlObject(HttpServletRequest request,
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

	protected SamlTransformer getTransformer() {
		return transformer;
	}

	protected ServiceProviderResolver getResolver() {
		return resolver;
	}

	protected ServiceProviderValidator getValidator() {
		return validator;
	}

	protected RequestMatcher getMatcher() {
		return matcher;
	}


	protected Saml2Object parseSamlRequest(HttpServletRequest request, HostedServiceProvider provider) {
		return parseSamlObject(request, provider, "SAMLRequest");
	}

	protected Saml2Object parseSamlResponse(HttpServletRequest request, HostedServiceProvider provider) {
		return parseSamlObject(request, provider, "SAMLResponse");
	}

	protected HostedServiceProvider resolveProvider(HttpServletRequest request) {
		HostedServiceProvider serviceProvider = getResolver().getServiceProvider(request);
		if (serviceProvider == null) {
			throw new SamlProviderNotFoundException("hosted");
		}
		return serviceProvider;
	}
}
