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
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.spi.opensaml.OpenSamlTransformer;

import sample.SimpleServiceProviderApplication.BeanConfigurationConditionExample;
import sample.SimpleServiceProviderApplication.SampleSamlBootConfiguration;
import sample.proof_of_concept.SamlConfigurationResolver;
import sample.proof_of_concept.implementation.StaticServiceProviderConfigurationResolver;

import static sample.proof_of_concept.SamlServiceProviderDsl.serviceProvider;

@Conditional(BeanConfigurationConditionExample.class)
@EnableWebSecurity
public class BootBeanSecurityConfiguration {

	@Bean //pick the underlying library
	public SamlTransformer samlTransformer() {
		return new OpenSamlTransformer();
	}

	@Bean
	public SamlConfigurationResolver<HostedServiceProviderConfiguration> spConfigurationResolver(
		SampleSamlBootConfiguration configuration) {
		HostedServiceProviderConfiguration spConfig = configuration.toSamlServerConfiguration().getServiceProvider();
		return new StaticServiceProviderConfigurationResolver(spConfig);
	}

	@Conditional(BeanConfigurationConditionExample.class)
	@Configuration
	@Order(1)
	public static class SamlSecurity extends WebSecurityConfigurerAdapter {

		private final SamlConfigurationResolver<HostedServiceProviderConfiguration> configurationResolver;
		private final SamlTransformer samlTransformer;

		public SamlSecurity(SamlConfigurationResolver<HostedServiceProviderConfiguration> configurationResolver,
							SamlTransformer samlTransformer) {
			this.configurationResolver = configurationResolver;
			this.samlTransformer = samlTransformer;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
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
			;
			http.apply(
				serviceProvider()
					.prefix("/saml/sp")
					.configurationResolver(configurationResolver)
					.samlTransformer(samlTransformer)
			);
		}
	}
}
