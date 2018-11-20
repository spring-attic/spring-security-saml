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
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.spi.opensaml.OpenSamlTransformer;

import sample.SimpleServiceProviderApplication.SampleSamlBootConfiguration;
import sample.proof_of_concept.ServiceProviderResolver;
import sample.proof_of_concept.implementation.ServiceProviderMetadataResolver;
import sample.proof_of_concept.implementation.StaticServiceProviderResolver;

import static sample.proof_of_concept.SamlServiceProviderDsl.serviceProvider;

@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	public SamlTransformer samlTransformer() {
		return new OpenSamlTransformer();
	}

	@Bean
	public ServiceProviderResolver serviceProviderResolver(SampleSamlBootConfiguration samlPropertyConfiguration) {
		HostedServiceProviderConfiguration spConfig =
			samlPropertyConfiguration
				.toSamlServerConfiguration()
				.getServiceProvider();

		ServiceProviderMetadataResolver serviceProviderMetadataResolver =
			new ServiceProviderMetadataResolver(samlTransformer());

		return new StaticServiceProviderResolver(serviceProviderMetadataResolver, spConfig);
	}

	@Configuration
	@Order(1)
	public static class SamlSecurity extends WebSecurityConfigurerAdapter {

		private final ServiceProviderResolver resolver;
		private final SamlTransformer samlTransformer;

		public SamlSecurity(ServiceProviderResolver resolver,
							SamlTransformer samlTransformer) {
			this.resolver = resolver;
			this.samlTransformer = samlTransformer;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http.apply(
				serviceProvider()
					.prefix("/saml/sp")
					.serviceProviderResolver(resolver)
					.samlTransformer(samlTransformer)
			);
		}
	}

	@Configuration
	@Order(2)
	public static class AppSecurity extends WebSecurityConfigurerAdapter {

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
		}
	}

}
