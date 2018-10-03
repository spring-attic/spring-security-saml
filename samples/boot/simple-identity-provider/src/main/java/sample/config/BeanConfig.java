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

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.SamlServerConfiguration;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderServerBeanConfiguration;
import org.springframework.security.saml.saml2.authentication.Assertion;

@Configuration
public class BeanConfig extends SamlIdentityProviderServerBeanConfiguration {
	private final AppConfig config;

	public BeanConfig(AppConfig config,
					  SamlTransformer samlTransformer,
					  SamlValidator samlValidator,
					  SamlMetadataCache samlMetadataCache,
					  SamlMessageStore<Assertion, HttpServletRequest> samlAssertionStore,
					  SamlConfigurationRepository<HttpServletRequest> samlConfigurationRepository) {
		super(samlTransformer, samlValidator, samlMetadataCache, samlAssertionStore, samlConfigurationRepository);
		this.config = config;
	}

	@Override
	protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
		return config.toSamlServerConfiguration();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder()
			.username("user")
			.password("password")
			.roles("USER")
			.build();
		return new InMemoryUserDetailsManager(userDetails);
	}
}
