/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.springframework.security.saml2.serviceprovider.web.filters;

import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

abstract class AbstractSamlServiceProviderFilter extends OncePerRequestFilter {

	private final Saml2Transformer transformer;
	private final Saml2ServiceProviderResolver resolver;
	private final Saml2ServiceProviderValidator validator;
	private final RequestMatcher matcher;
	private final Saml2ServiceProviderMethods spUtils;

	public AbstractSamlServiceProviderFilter(Saml2Transformer transformer,
											 Saml2ServiceProviderResolver resolver,
											 Saml2ServiceProviderValidator validator,
											 RequestMatcher matcher) {
		this.transformer = transformer;
		this.resolver = resolver;
		this.validator = validator;
		this.matcher = matcher;
		this.spUtils = new Saml2ServiceProviderMethods(transformer, resolver, validator);
	}



	RequestMatcher getMatcher() {
		return matcher;
	}

	protected Saml2ServiceProviderMethods getSpUtils() {
		return spUtils;
	}

	protected Saml2Transformer getTransformer() {
		return transformer;
	}

	protected Saml2ServiceProviderResolver getResolver() {
		return resolver;
	}

	protected Saml2ServiceProviderValidator getValidator() {
		return validator;
	}

}
