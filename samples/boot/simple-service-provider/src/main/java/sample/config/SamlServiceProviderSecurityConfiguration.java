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

import javax.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.ServiceProvider;
import org.springframework.security.saml.provider.service.ServiceProviderMetadataFilter;
import org.springframework.security.saml.provider.service.authentication.GenericErrorAuthenticationFailureHandler;
import org.springframework.security.saml.provider.service.authentication.SamlResponseAuthenticationFilter;
import org.springframework.security.saml.provider.service.authentication.SamlServiceProviderLogoutFilter;
import org.springframework.security.saml.provider.service.authentication.SimpleAuthenticationManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class SamlServiceProviderSecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final SamlProviderProvisioning<ServiceProvider> provisioning;

	public SamlServiceProviderSecurityConfiguration(SamlProviderProvisioning<ServiceProvider> provisioning) {
		this.provisioning = provisioning;
	}

	@Bean
	public Filter metadataFilter() {
		return new ServiceProviderMetadataFilter(provisioning);
	}

	@Bean
	public Filter authenticationRequestFilter() {
		return new SamlAuthenticationRequestFilter(provisioning);
	}

	@Bean
	public Filter authenticationResponseFilter() {
		SamlResponseAuthenticationFilter authenticationFilter =
			new SamlResponseAuthenticationFilter(provisioning);
		authenticationFilter.setAuthenticationManager(new SimpleAuthenticationManager());
		authenticationFilter.setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
		authenticationFilter.setAuthenticationFailureHandler(new GenericErrorAuthenticationFailureHandler());
		return authenticationFilter;
	}

	@Bean
	public Filter samlLogoutFilter() {
		return new SamlServiceProviderLogoutFilter(
			provisioning,
			new SimpleUrlLogoutSuccessHandler(),
			new SecurityContextLogoutHandler()
		);
	}



	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.addFilterAfter(metadataFilter(), BasicAuthenticationFilter.class)
			.addFilterAfter(authenticationRequestFilter(), metadataFilter().getClass())
			.addFilterAfter(authenticationResponseFilter(), authenticationRequestFilter().getClass())
			.addFilterAfter(samlLogoutFilter(), authenticationResponseFilter().getClass())
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/saml/sp/**").permitAll() //TODO - based on configuration
			.anyRequest().authenticated()
			.and()
			.formLogin().loginPage("/saml/sp/select") //TODO - based on configuration
		;
	}
}
