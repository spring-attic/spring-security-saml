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
package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.provider.HostBasedSamlServiceProviderProvisioning;
import org.springframework.security.saml.provider.SamlConfigurationRepository;
import org.springframework.security.saml.provider.SamlProviderProvisioning;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.StaticSamlConfigurationRepository;
import org.springframework.security.saml.provider.service.ServiceProvider;
import org.springframework.security.saml.spi.deprecated.DefaultSpConfiguration;

@Configuration
public class SampleSpConfiguration extends DefaultSpConfiguration {

	@Bean
	SamlConfigurationRepository configurationRepository(AppConfig config) {
		return new StaticSamlConfigurationRepository(config);
	}

	@Bean
	public SamlProviderProvisioning<ServiceProvider> samlProviderProvisioning(
		SamlConfigurationRepository repository,
		SamlMetadataCache cache
	) {
		return new HostBasedSamlServiceProviderProvisioning(
			repository,
			transformer(),
			validator(),
			cache
		);
	}

	@Override
	@Bean
	public SamlMessageHandler metadataHandler(SamlServerConfiguration configuration) {
		return new DoNothingMessageHandler();
	}
}
