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

package org.springframework.security.saml.provider.config;

import java.time.Clock;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.DefaultSessionAssertionStore;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.web.client.RestOperations;

/**
 * Sensible defaults - core beans needed for SAML
 */
public class SamlServerBeanConfiguration {

	public SamlConfigurationRepository samlConfigurationRepository() {
		return new ThreadLocalSamlConfigurationRepository(
			new StaticSamlConfigurationRepository(null)
		);
	}


	public DefaultSessionAssertionStore samlAssertionStore() {
		return new DefaultSessionAssertionStore();
	}

	public SamlTemplateEngine samlTemplateEngine() {
		return new OpenSamlVelocityEngine();
	}

	public SamlTransformer samlTransformer() {
		return new DefaultSamlTransformer(samlImplementation());
	}

	public SpringSecuritySaml samlImplementation() {
		return new OpenSamlImplementation(samlTime()).init();
	}

	public Clock samlTime() {
		return Clock.systemUTC();
	}

	public SamlValidator samlValidator() {
		return new DefaultValidator(samlImplementation());
	}

	public SamlMetadataCache samlMetadataCache() {
		return new DefaultMetadataCache(
			samlTime(),
			samlValidatingNetworkHandler(),
			samlNonValidatingNetworkHandler()
		);
	}

	public RestOperations samlValidatingNetworkHandler() {
		return new Network(4000, 8000).get(false);
	}

	public RestOperations samlNonValidatingNetworkHandler() {
		return new Network(4000, 8000).get(true);
	}

}
