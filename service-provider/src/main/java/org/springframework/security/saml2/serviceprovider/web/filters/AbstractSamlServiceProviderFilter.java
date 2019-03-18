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

import org.springframework.security.saml2.SamlTransformer;
import org.springframework.security.saml2.provider.validation.ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.ServiceProviderResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

abstract class AbstractSamlServiceProviderFilter extends OncePerRequestFilter {

	private final SamlTransformer transformer;
	private final ServiceProviderResolver resolver;
	private final ServiceProviderValidator validator;
	private final RequestMatcher matcher;
	private final SamlServiceProviderUtils spUtils;

	public AbstractSamlServiceProviderFilter(SamlTransformer transformer,
											 ServiceProviderResolver resolver,
											 ServiceProviderValidator validator,
											 RequestMatcher matcher) {
		this.transformer = transformer;
		this.resolver = resolver;
		this.validator = validator;
		this.matcher = matcher;
		this.spUtils = new SamlServiceProviderUtils(transformer, resolver, validator);
	}



	RequestMatcher getMatcher() {
		return matcher;
	}

	protected SamlServiceProviderUtils getSpUtils() {
		return spUtils;
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

}
