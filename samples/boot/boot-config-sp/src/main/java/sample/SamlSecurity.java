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

package sample;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.boot.registration.SamlBootConfiguration;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.serviceprovider.ServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.configuration.OpenSamlTransformerConfiguration;
import org.springframework.security.saml.serviceprovider.spi.SingletonServiceProviderConfigurationResolver;

import static org.springframework.security.saml.serviceprovider.SamlServiceProviderConfigurer.saml2Login;

@EnableWebSecurity
@Import({SamlBootConfiguration.class, OpenSamlTransformerConfiguration.class})
@Configuration
public class SamlSecurity extends WebSecurityConfigurerAdapter {

	private final HostedServiceProviderConfiguration configuration;

	public SamlSecurity(HostedServiceProviderConfiguration configuration) {
		this.configuration = configuration;
	}

	/*
	 * Exposed as a SpyBean in unit tests
	 */
	@Bean
	public ServiceProviderConfigurationResolver serviceProviderConfigurationResolver() {
		return new SingletonServiceProviderConfigurationResolver(configuration);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.antMatcher("/**")
				.authorizeRequests()
				.antMatchers("/**").authenticated()
			.and()
				.logout()
			.and()
				.apply(
					saml2Login()
						.prefix("/saml/sp")
						.configurationResolver(serviceProviderConfigurationResolver())
			);
		// @formatter:on
	}
}

