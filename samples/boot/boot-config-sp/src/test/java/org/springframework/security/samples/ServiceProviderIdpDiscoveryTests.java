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
package org.springframework.security.samples;

import java.util.LinkedList;
import java.util.List;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml.boot.registration.RemoteIdentityProviderConfiguration;
import org.springframework.security.saml.configuration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SAML Service Provider IDP Discovery")
public class ServiceProviderIdpDiscoveryTests extends AbstractServiceProviderTestBase {

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("home page is secure")
	void secureHomePage() throws Exception {
		mockMvc.perform(
			get("/")
		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/saml/sp/select?redirect=true"))
		;
	}

	@Test
	@DisplayName("single provider redirects automatically")
	void singleProviderAutomaticRedirect() throws Exception {
		mockMvc.perform(
			get("http://localhost/saml/sp/select?redirect=true")

		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl(
				"http://localhost/saml/sp/discovery?idp=http%3A%2F%2Fsimplesaml-for-spring-saml.cfapps.io%2Fsaml2%2Fidp%2Fmetadata.php"))
		;
	}

	@Test
	@DisplayName("displays single IDP selection")
	void idpSelection() throws Exception {
		//no redirect without redirect parameter
		mockMvc.perform(
			get("http://localhost/saml/sp/select")

		)
			.andExpect(status().is2xxSuccessful())
			.andExpect(content().string(containsString(
				"http://localhost/saml/sp/discovery?idp=http%3A%2F%2Fsimplesaml-for-spring-saml.cfapps.io%2Fsaml2%2Fidp%2Fmetadata.php"
			)))
		;
	}


	@Test
	@DisplayName("multiple IDPs are always displayed")
	void multipleIdpSelection() throws Exception {
		List<RemoteIdentityProviderConfiguration> providers = bootConfiguration.getServiceProvider().getProviders();
		List<ExternalIdentityProviderConfiguration> list = new LinkedList<>();
		list.add(providers.get(0).toExternalIdentityProviderConfiguration());
		providers.get(0).setAlias(providers.get(0).getAlias() + "-2");
		providers.get(0).setLinktext("A Secondary SimpleSAML Provider");
		list.add(providers.get(0).toExternalIdentityProviderConfiguration());
		mockConfig(
			builder ->
				builder.providers(list)
		);

		mockMvc.perform(
			get("http://localhost/saml/sp/select?redirect=true")

		)
			.andExpect(status().is2xxSuccessful())
			.andExpect(content().string(containsString(">Simple SAML PHP IDP<")))
			.andExpect(content().string(containsString(">A Secondary SimpleSAML Provider<")))
		;
	}

	@Test
	@DisplayName("initiate login by SP")
	void spInitiated() throws Exception {
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		assertThat(
			authn.getDestination().getLocation(),
			equalTo("http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php")
		);
		assertThat(
			authn.getOriginEntityId(),
			equalTo("spring.security.saml.sp.id")
		);
		assertThat(
			authn.getSignature(),
			notNullValue()
		);

	}

	@Test
	@DisplayName("authentication request is not signed")
	void authNRequestNotSigned() throws Exception {
		mockConfig(builder -> builder.signRequests(false));
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		assertThat(
			authn.getDestination().getLocation(),
			equalTo("http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php")
		);
		assertThat(
			authn.getOriginEntityId(),
			equalTo("spring.security.saml.sp.id")
		);
		assertThat(
			authn.getSignature(),
			nullValue()
		);
	}

}
