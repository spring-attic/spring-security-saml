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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saved_for_later.SamlValidator;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.DefaultValidator;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;

import static sample.proof_of_concept.SamlSpDsl.serviceProvider;

@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	public SpringSecuritySaml samlImplementation() {
		return new OpenSamlImplementation(Clock.systemUTC()).init();
	}

	@Bean
	public SamlTemplateEngine samlTemplateEngine() {
		return new OpenSamlVelocityEngine(true);
	}

	@Bean
	public SamlTransformer samlTransformer() {
		return new DefaultSamlTransformer(
			samlImplementation()
		);
	}

	@Bean
	public SamlValidator samlValidator() {
		return new DefaultValidator(samlImplementation());
	}

	@Configuration
	@Order(1)
	public static class SamlSecurity extends WebSecurityConfigurerAdapter {

		private final SamlPropertyConfiguration samlPropertyConfiguration;
		private final SamlValidator samlValidator;
		private final SamlTransformer samlTransformer;
		private final SamlTemplateEngine samlTemplateEngine;

		public SamlSecurity(SamlPropertyConfiguration samlPropertyConfiguration,
							SamlValidator samlValidator,
							SamlTransformer samlTransformer,
							SamlTemplateEngine samlTemplateEngine) {
			this.samlPropertyConfiguration = samlPropertyConfiguration;
			this.samlValidator = samlValidator;
			this.samlTransformer = samlTransformer;
			this.samlTemplateEngine = samlTemplateEngine;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http.apply(
				serviceProvider()
					.setSamlTransformer(samlTransformer)
					.setSamlValidator(samlValidator)
					.setSpConfig(samlPropertyConfiguration.toSamlServerConfiguration().getServiceProvider())
					.setSamlTemplateEngine(samlTemplateEngine)
			);
		}
	}

	@Configuration
	public static class AppSecurity extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.antMatcher("/**")
				.authorizeRequests()
				.antMatchers("/**").authenticated()
				.and()
				.formLogin().loginPage("/saml/sp/select")
			;
		}
	}

}
