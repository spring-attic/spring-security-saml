/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml2.samples;

import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.Saml2ServiceProviderConfigurer;
import org.springframework.security.saml2.boot.configuration.Saml2BootConfiguration;
import org.springframework.security.saml2.serviceprovider.bean.OpenSaml2TransformerBeans;
import org.springframework.security.saml2.serviceprovider.servlet.bean.Saml2ServiceProviderBeans;

import static org.springframework.security.config.annotation.web.configurers.Saml2ServiceProviderConfigurer.saml2Login;

@Import
	({
		 Saml2BootConfiguration.class,    //properties from application.yml
		 OpenSaml2TransformerBeans.class, //OpenSAML as the underlying parsing library
		 Saml2ServiceProviderBeans.class  //Service Provider beans used by saml2login()
	 })
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.mvcMatcher("/**")
				.authorizeRequests()
				.anyRequest().authenticated()
			.and()
				.apply(
					Saml2ServiceProviderConfigurer.saml2Login()
				)
		;
		// @formatter:on
	}
}

