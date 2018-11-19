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

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.boot.SamlBootConfiguration;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.DefaultSamlValidator;
import org.springframework.security.saml.spi.SamlValidator;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.VelocityTemplateEngine;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

import sample.proof_of_concept.ServiceProviderResolver;
import sample.proof_of_concept.implementation.ServiceProviderMetadataResolver;
import sample.proof_of_concept.implementation.StaticServiceProviderResolver;

import static sample.proof_of_concept.SamlServiceProviderDsl.serviceProvider;

@EnableWebSecurity
public class SecurityConfiguration {

	@Configuration
	public static class SamlPropertyConfiguration extends SamlBootConfiguration {}

	@Bean
	public SpringSecuritySaml samlImplementation() {
		return new OpenSamlImplementation(Clock.systemUTC()).init();
	}

	@Bean
	public SamlTemplateEngine samlTemplateEngine() {
		return new VelocityTemplateEngine(true);
	}

	@Bean
	public SamlTransformer samlTransformer() {
		return new DefaultSamlTransformer(
			samlImplementation()
		);
	}

	@Bean
	public SamlValidator samlValidator() {
		return new DefaultSamlValidator(samlImplementation());
	}

	@Bean
	public ServiceProviderMetadataResolver serviceProviderMetadata() {
		return new ServiceProviderMetadataResolver(samlTransformer());
	}

	@Bean
	public ServiceProviderResolver serviceProviderResolver(SamlPropertyConfiguration samlPropertyConfiguration) {
		HostedServiceProviderConfiguration spConfig =
			samlPropertyConfiguration.toSamlServerConfiguration().getServiceProvider();
		return new StaticServiceProviderResolver(serviceProviderMetadata(), spConfig);
	}

	@Configuration
	@Order(1)
	public static class SamlSecurity extends WebSecurityConfigurerAdapter {

		private final SpringSecuritySaml implementation;
		private final ServiceProviderResolver resolver;
		private final SamlValidator samlValidator;
		private final SamlTransformer samlTransformer;
		private final SamlTemplateEngine samlTemplateEngine;

		public SamlSecurity(SpringSecuritySaml implemenation,
							ServiceProviderResolver resolver,
							SamlValidator samlValidator,
							SamlTransformer samlTransformer,
							SamlTemplateEngine samlTemplateEngine) {
			this.implementation = implemenation;
			this.resolver = resolver;
			this.samlValidator = samlValidator;
			this.samlTransformer = samlTransformer;
			this.samlTemplateEngine = samlTemplateEngine;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http.apply(
				serviceProvider()
					.prefix("/saml/sp")
					.setImplementation(implementation)
					.serviceProviderResolver(resolver)
					.samlTransformer(samlTransformer)
					.samlValidator(samlValidator)
					.samlTemplateEngine(samlTemplateEngine)
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
