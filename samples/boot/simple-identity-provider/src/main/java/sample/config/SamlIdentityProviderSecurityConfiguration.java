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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml.provider.identity.IdentityProvider;
import org.springframework.security.saml.provider.identity.IdentityProviderMetadataFilter;
import org.springframework.security.saml.provider.identity.IdpInitiatedLoginFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.spi.DefaultSessionAssertionStore;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class SamlIdentityProviderSecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final SamlProviderProvisioning<IdentityProvider> provisioning;

	public SamlIdentityProviderSecurityConfiguration(SamlProviderProvisioning<IdentityProvider> provisioning) {
		this.provisioning = provisioning;
	}

	@Bean
	public DefaultSessionAssertionStore assertionStore() {
		return new DefaultSessionAssertionStore();
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

	@Bean
	public Filter metadataFilter() {
		return new IdentityProviderMetadataFilter(provisioning);
	}

	@Bean
	public Filter idpInitatedLoginFilter() {
		return new IdpInitiatedLoginFilter(provisioning, assertionStore());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.addFilterAfter(metadataFilter(), BasicAuthenticationFilter.class)
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/saml/idp/metadata").permitAll()
			.anyRequest().authenticated()
			.and()
			.formLogin()
		;
	}
}
