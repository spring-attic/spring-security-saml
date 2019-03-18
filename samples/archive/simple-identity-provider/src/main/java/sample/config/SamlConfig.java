/*
 * Copyright 2002-2019 the original author or authors.
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

package sample.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.SamlMetadataCache;
import org.springframework.security.saml2.SamlTemplateEngine;
import org.springframework.security.saml2.SamlTransformer;
import org.springframework.security.saml2.SamlValidator;
import org.springframework.security.saml2.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml2.provider.config.SamlServerBeanConfiguration;
import org.springframework.security.saml2.provider.config.StaticSamlConfigurationRepository;
import org.springframework.security.saml2.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml2.serviceprovider.spi.DefaultSessionAssertionStore;
import org.springframework.security.saml2.serviceprovider.spi.SpringSecuritySaml;
import org.springframework.web.client.RestOperations;

@Configuration
public class SamlConfig extends SamlServerBeanConfiguration {

	@Bean
	public SamlConfigurationRepository samlConfigurationRepository(SamlPropertyConfiguration config) {
		return new ThreadLocalSamlConfigurationRepository(
			new StaticSamlConfigurationRepository(config.toSamlServerConfiguration())
		);
	}

	@Bean
	@Override
	public DefaultSessionAssertionStore samlAssertionStore() {
		return super.samlAssertionStore();
	}

	@Bean
	@Override
	public SamlTemplateEngine samlTemplateEngine() {
		return super.samlTemplateEngine();
	}

	@Bean
	@Override
	public SamlTransformer samlTransformer() {
		return super.samlTransformer();
	}

	@Bean
	@Override
	public SpringSecuritySaml samlImplementation() {
		return super.samlImplementation();
	}

	@Bean
	@Override
	public Clock samlTime() {
		return super.samlTime();
	}

	@Bean
	@Override
	public SamlValidator samlValidator() {
		return super.samlValidator();
	}

	@Bean
	@Override
	public SamlMetadataCache samlMetadataCache() {
		return super.samlMetadataCache();
	}

	@Bean
	@Override
	public RestOperations samlValidatingNetworkHandler() {
		return super.samlValidatingNetworkHandler();
	}

	@Bean
	@Override
	public RestOperations samlNonValidatingNetworkHandler() {
		return super.samlNonValidatingNetworkHandler();
	}
}
