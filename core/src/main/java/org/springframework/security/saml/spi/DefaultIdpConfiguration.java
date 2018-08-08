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

package org.springframework.security.saml.spi;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.provider.SamlServerConfiguration;

public class DefaultIdpConfiguration extends AbstractProviderConfiguration {
	@Bean
	@Override
	public List<SamlMessageHandler> handlers(SamlServerConfiguration configuration) {
		return Arrays.asList(
			metadataHandler(configuration),
			idpRequestHandler(configuration),
			idpInitiationHandler(configuration),
			logoutHandler(configuration)
		);
	}

	@Bean
	public SamlMessageHandler idpRequestHandler(SamlServerConfiguration configuration) {
		return new DefaultIdpRequestHandler()
			.setSamlDefaults(samlDefaults())
			.setNetwork(network(configuration))
			.setResolver(resolver())
			.setTransformer(transformer())
			.setConfiguration(configuration)
			.setValidator(validator())
			.setSamlTemplateEngine(samlTemplateEngine())
			.setPostBindingTemplate("/templates/saml2-post-binding.vm")
			.setStore(assertionStore());
	}

	@Bean
	public SamlMessageHandler idpInitiationHandler(SamlServerConfiguration configuration) {
		return new DefaultIdpInitiationHandler()
			.setSamlDefaults(samlDefaults())
			.setNetwork(network(configuration))
			.setResolver(resolver())
			.setTransformer(transformer())
			.setConfiguration(configuration)
			.setValidator(validator())
			.setSamlTemplateEngine(samlTemplateEngine())
			.setPostBindingTemplate("/templates/saml2-post-binding.vm")
			.setStore(assertionStore());
	}
}
