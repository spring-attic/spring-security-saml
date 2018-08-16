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

package org.springframework.security.saml.provider.provisioning;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.springframework.util.StringUtils.hasText;

public class AbstractHostbasedSamlProviderProvisioning {

	private final SamlConfigurationRepository<HttpServletRequest> configuration;
	private final SamlTransformer transformer;
	private final SamlValidator validator;
	private final SamlMetadataCache cache;

	public AbstractHostbasedSamlProviderProvisioning(SamlConfigurationRepository<HttpServletRequest> configuration,
													 SamlTransformer transformer,
													 SamlValidator validator,
													 SamlMetadataCache cache) {
		this.configuration = configuration;
		this.transformer = transformer;
		this.validator = validator;
		this.cache = cache;
	}

	public String getBasePath(HttpServletRequest request) {
		return request.getScheme() +
			"://" +
			request.getServerName() +
			":" +
			request.getServerPort() +
			request.getContextPath();
	}

	protected String getAliasPath(LocalProviderConfiguration configuration) {
		try {
			return hasText(configuration.getAlias()) ?
				UriUtils.encode(configuration.getAlias(), StandardCharsets.ISO_8859_1.name()) :
				UriUtils.encode(configuration.getEntityId(), StandardCharsets.ISO_8859_1.name());
		} catch (UnsupportedEncodingException e) {
			throw new SamlException(e);
		}
	}

	protected Endpoint getEndpoint(String baseUrl, String path, Binding binding, int index, boolean isDefault) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
		builder.pathSegment(path);
		return getEndpoint(builder.build().toUriString(), binding, index, isDefault);
	}

	protected Endpoint getEndpoint(String url, Binding binding, int index, boolean isDefault) {
		return
			new Endpoint()
				.setIndex(index)
				.setBinding(binding)
				.setLocation(url)
				.setDefault(isDefault)
				.setIndex(index);
	}


	public SamlConfigurationRepository<HttpServletRequest> getConfiguration() {
		return configuration;
	}

	public SamlTransformer getTransformer() {
		return transformer;
	}

	public SamlValidator getValidator() {
		return validator;
	}

	public SamlMetadataCache getCache() {
		return cache;
	}
}
