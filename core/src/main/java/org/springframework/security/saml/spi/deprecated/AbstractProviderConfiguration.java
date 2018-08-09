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

package org.springframework.security.saml.spi.deprecated;

import java.time.Clock;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlProcessingFilter;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.DefaultSamlObjectResolver;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.DefaultSessionAssertionStore;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.security.saml.util.Network;

public abstract class AbstractProviderConfiguration {

	@Bean
	public abstract List<SamlMessageHandler> handlers(SamlServerConfiguration configuration);

	@Bean
	public SamlProcessingFilter samlFilter(List<SamlMessageHandler> handlers) {
		return new SamlProcessingFilter()
			.setHandlers(handlers);
	}

	@Bean
	public SamlMessageHandler metadataHandler(SamlServerConfiguration configuration) {
		return new DefaultMetadataHandler()
			.setSamlDefaults(samlDefaults())
			.setNetwork(network(configuration))
			.setResolver(resolver())
			.setTransformer(transformer())
			.setConfiguration(configuration);
	}

	@Bean
	public SamlMessageHandler logoutHandler(SamlServerConfiguration configuration) {
		return new DefaultLogoutHandler()
			.setSamlDefaults(samlDefaults())
			.setNetwork(network(configuration))
			.setResolver(resolver())
			.setTransformer(transformer())
			.setConfiguration(configuration)
			.setValidator(validator())
			.setAssertionStore(assertionStore());
	}

	@Bean
	public DefaultSessionAssertionStore assertionStore() {
		return new DefaultSessionAssertionStore();
	}


	@Bean
	public SamlTemplateEngine samlTemplateEngine() {
		return new OpenSamlVelocityEngine();
	}

	@Bean
	public SamlTransformer transformer() {
		return new DefaultSamlTransformer(implementation());
	}

	@Bean
	public SpringSecuritySaml implementation() {
		return new OpenSamlImplementation(time());
	}

	@Bean
	public Clock time() {
		return Clock.systemUTC();
	}

	@Bean
	public SamlValidator validator() {
		return new DefaultValidator(implementation());
	}

	@Bean
	public SamlDefaults samlDefaults() {
		return new SamlDefaults(time());
	}

	@Bean
	public SamlObjectResolver resolver() {
		return new DefaultSamlObjectResolver();
	}

	@Bean
	public SamlMetadataCache cache(Network network) {
		return new DefaultMetadataCache(time(), network);
	}

	@Bean
	public Network network(SamlServerConfiguration configuration) {
		Network result = new Network();
		if (configuration!=null && configuration.getNetwork()!=null) {
			result
				.setConnectTimeoutMillis(configuration.getNetwork().getConnectTimeout())
				.setReadTimeoutMillis(configuration.getNetwork().getReadTimeout());
		}
		return result;
	}
}
