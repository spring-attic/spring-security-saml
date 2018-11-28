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
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.boot.registration.SamlBootConfiguration;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.serviceprovider.ServiceProviderConfigurationResolver;
import org.springframework.security.saml.serviceprovider.annotation.EnableOpenSaml;
import org.springframework.security.saml.serviceprovider.implementation.SingletonServiceProviderConfigurationResolver;

import static org.springframework.security.saml.serviceprovider.SamlServiceProviderConfigurer.serviceProvider;

@EnableWebSecurity
@EnableOpenSaml
@Import({SamlBootConfiguration.class})
@Configuration
@Order(1)
public class SamlSecurity extends WebSecurityConfigurerAdapter {

	private final HostedServiceProviderConfiguration configuration;
	private final SamlTransformer samlTransformer;

	public SamlSecurity(HostedServiceProviderConfiguration configuration,
						SamlTransformer samlTransformer) {
		this.configuration = configuration;
		this.samlTransformer = samlTransformer;
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
				.formLogin().loginPage("/saml/sp/select")
			.and()
				.logout()
				.logoutUrl("/logout")
				.logoutSuccessUrl("/saml/sp/select")
			.and()
				.apply(
					serviceProvider()
						.prefix("/saml/sp")
						.configurationResolver(serviceProviderConfigurationResolver())
						.samlTransformer(samlTransformer)
			);
		// @formatter:on
	}
}

