/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.saml.serviceprovider.web.filters;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.provider.HostedServiceProvider;
import org.springframework.security.saml.serviceprovider.web.ServiceProviderResolver;
import org.springframework.security.saml.provider.validation.ServiceProviderValidator;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.saml.serviceprovider.web.filters.SamlFilter.SAML_PROVIDER;
import static org.springframework.security.saml.serviceprovider.web.filters.SamlFilter.SAML_REQUEST;
import static org.springframework.security.saml.serviceprovider.web.filters.SamlFilter.SAML_RESPONSE;
import static org.springframework.util.StringUtils.hasText;

public class SamlProcessingFilter extends OncePerRequestFilter {


	private final SamlTransformer transformer;
	private final ServiceProviderResolver resolver;
	private final ServiceProviderValidator validator;
	private final RequestMatcher matcher;

	public SamlProcessingFilter(SamlTransformer transformer,
								ServiceProviderResolver resolver,
								ServiceProviderValidator validator,
								RequestMatcher matcher) {
		this.transformer = transformer;
		this.resolver = resolver;
		this.validator = validator;
		this.matcher = matcher;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws ServletException, IOException {
		if (matcher.matches(request)) {
			HostedServiceProvider provider = resolveProvider(request);
			parseSamlRequest(request, provider);
			parseSamlResponse(request, provider);
		}
		chain.doFilter(request, response);
	}

	protected Saml2Object parseSamlRequest(HttpServletRequest request, HostedServiceProvider provider) {
		return parseSamlObject(request, provider, "SAMLRequest", SAML_REQUEST);
	}

	protected Saml2Object parseSamlResponse(HttpServletRequest request, HostedServiceProvider provider) {
		return parseSamlObject(request, provider, "SAMLResponse", SAML_RESPONSE);
	}

	protected HostedServiceProvider resolveProvider(HttpServletRequest request) {
		HostedServiceProvider serviceProvider = resolver.getServiceProvider(request);
		if (serviceProvider == null) {
			throw new SamlProviderNotFoundException("hosted");
		}
		request.setAttribute(SAML_PROVIDER, serviceProvider);
		return serviceProvider;
	}

	private Saml2Object parseSamlObject(HttpServletRequest request,
								 HostedServiceProvider provider,
								 String parameterName, String attributeName) {
		Saml2Object result = null;
		String rs = request.getParameter(parameterName);
		if (hasText(rs)) {
			String xml = transformer.samlDecode(rs, HttpMethod.GET.matches(request.getMethod()));
			result = transformer.fromXml(xml, null, provider.getConfiguration().getKeys());
			if (result instanceof SignableSaml2Object) {
				SignableSaml2Object signableSaml2Object = (SignableSaml2Object) result;
				IdentityProviderMetadata idp = provider.getRemoteProvider(signableSaml2Object.getOriginEntityId());
				if (idp == null) {
					throw new SamlProviderNotFoundException(result.getOriginEntityId());
				}
				try {
					Signature signature =
						validator.validateSignature(signableSaml2Object, idp.getIdentityProvider().getKeys());
					signableSaml2Object.setSignature(signature);
				} catch (SignatureException e) {
				}
			}
			request.setAttribute(attributeName, result);
		}
		return result;
	}
}
