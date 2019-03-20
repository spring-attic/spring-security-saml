/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
import javax.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.HostedProviderService;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.DefaultSessionAssertionStore;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.web.client.RestOperations;

public abstract class AbstractSamlServerBeanConfiguration<T extends HostedProviderService> {

	public abstract SamlProviderProvisioning<T> getSamlProvisioning();

	@Bean
	public DefaultSessionAssertionStore samlAssertionStore() {
		return new DefaultSessionAssertionStore();
	}

	@Bean
	public SamlTemplateEngine samlTemplateEngine() {
		return new OpenSamlVelocityEngine();
	}

	@Bean
	public SamlTransformer samlTransformer() {
		return new DefaultSamlTransformer(samlImplementation());
	}

	@Bean
	public SpringSecuritySaml samlImplementation() {
		return new OpenSamlImplementation(samlTime()).init();
	}

	@Bean
	public Clock samlTime() {
		return Clock.systemUTC();
	}

	@Bean
	public SamlValidator samlValidator() {
		return new DefaultValidator(samlImplementation());
	}

	@Bean
	public SamlMetadataCache samlMetadataCache() {
		return new DefaultMetadataCache(
			samlTime(),
			samlValidatingNetworkHandler(),
			samlNonValidatingNetworkHandler()
		);
	}

	public Filter samlConfigurationFilter() {
		return new ThreadLocalSamlConfigurationFilter(
			(ThreadLocalSamlConfigurationRepository) samlConfigurationRepository()
		);
	}

	public SamlConfigurationRepository samlConfigurationRepository() {
		return new ThreadLocalSamlConfigurationRepository(
			new StaticSamlConfigurationRepository(getDefaultHostSamlServerConfiguration())
		);
	}

	protected abstract SamlServerConfiguration getDefaultHostSamlServerConfiguration();

	private int getNetworkHandlerConnectTimeout() {
		if (getDefaultHostSamlServerConfiguration() != null && getDefaultHostSamlServerConfiguration().getNetwork() != null) {
			NetworkConfiguration networkConfiguration = getDefaultHostSamlServerConfiguration().getNetwork();
			return networkConfiguration.getConnectTimeout();
		}
		return 5000;
	}

	private int getNetworkHandlerReadTimeout() {
		if (getDefaultHostSamlServerConfiguration() != null && getDefaultHostSamlServerConfiguration().getNetwork() != null) {
			NetworkConfiguration networkConfiguration = getDefaultHostSamlServerConfiguration().getNetwork();
			return networkConfiguration.getReadTimeout();
		}
		return 10000;
	}

	@Bean
	public RestOperations samlValidatingNetworkHandler() {
		return new Network(getNetworkHandlerConnectTimeout(), getNetworkHandlerReadTimeout()).get(false);
	}

	@Bean
	public RestOperations samlNonValidatingNetworkHandler() {
		return new Network(getNetworkHandlerConnectTimeout(), getNetworkHandlerReadTimeout()).get(true);
	}
}
