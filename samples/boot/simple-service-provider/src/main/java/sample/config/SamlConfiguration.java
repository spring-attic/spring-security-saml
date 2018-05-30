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

import java.time.Clock;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlProcessingFilter;
import org.springframework.security.saml.SamlProcessor;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.spi.DefaultAuthnRequestProcessor;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.DefaultMetadataProcessor;
import org.springframework.security.saml.spi.DefaultSamlObjectResolver;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.Defaults;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.security.saml.util.Network;

@Configuration
public class SamlConfiguration {

	@Bean
	public SamlProcessingFilter samlFilter(List<SamlProcessor> processors) {
		return new SamlProcessingFilter()
			.setProcessors(processors);
	}

	@Bean
	public List<SamlProcessor> processors(SamlServerConfiguration configuration) {
		return Arrays.asList(
			metadataProcessor(configuration)
		);
	}

	@Bean
	public SamlProcessor metadataProcessor(SamlServerConfiguration configuration) {
		return new DefaultMetadataProcessor()
			.setDefaults(defaults())
			.setNetwork(network())
			.setResolver(resolver())
			.setTransformer(transformer())
			.setConfiguration(configuration);
	}

	@Bean
	public SamlProcessor discoveryProcessor(SamlServerConfiguration configuration) {
		return new DefaultAuthnRequestProcessor()
			.setDefaults(defaults())
			.setNetwork(network())
			.setResolver(resolver())
			.setTransformer(transformer())
			.setConfiguration(configuration);
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
	public Defaults defaults() {
		return new Defaults(time());
	}

	@Bean
	public SamlObjectResolver resolver() {
		return new DefaultSamlObjectResolver();
	}

	@Bean
	public DefaultMetadataCache cache() {
		return new DefaultMetadataCache(time(), network());
	}

	@Bean
	public Network network() {
		return new Network();
	}
}
