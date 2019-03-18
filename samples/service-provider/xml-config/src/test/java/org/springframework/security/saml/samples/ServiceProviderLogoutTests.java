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
package org.springframework.security.saml.samples;

import java.net.URI;
import java.time.Clock;
import java.util.Collections;
import java.util.Map;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.model.authentication.Assertion;
import org.springframework.security.saml.model.authentication.LogoutRequest;
import org.springframework.security.saml.model.authentication.LogoutResponse;
import org.springframework.security.saml.model.authentication.StatusCode;
import org.springframework.security.saml.model.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.model.metadata.NameId;
import org.springframework.security.saml.model.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.serviceprovider.authentication.DefaultSamlAuthentication;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.saml.helper.SamlTestObjectHelper.queryParams;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SAML Service Provider Single Logout")
public class ServiceProviderLogoutTests extends AbstractServiceProviderTestBase {

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "org/springframework/security/saml/samples")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("SP initiated logout")
	void initiateLogout() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idp.getEntityId(),
			sp.getEntityId(),
			null,
			null
		);

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		String redirect = mockMvc.perform(
			get(location)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andReturn()
			.getResponse()
			.getHeader("Location");

		Map<String, String> params = queryParams(new URI(redirect));
		String request = params.get("SAMLRequest");
		assertNotNull(request);
		LogoutRequest lr = (LogoutRequest) transformer.fromXml(
			transformer.samlDecode(request, true),
			null,
			null
		);
		assertNotNull(lr);
	}

	@Test
	@DisplayName("SP receives logout request")
	void receiveLogoutRequest() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idp.getEntityId(),
			sp.getEntityId(),
			null,
			null
		);
		LogoutRequest request = helper.logoutRequest(
			sp,
			idp,
			assertion.getSubject().getPrincipal()
		);

		String xml = transformer.toXml(request);
		String param = transformer.samlEncode(xml, true);

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		String redirect = mockMvc.perform(
			get(location)
				.param("SAMLRequest", param)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andReturn()
			.getResponse()
			.getHeader("Location");

		Map<String, String> params = queryParams(new URI(redirect));
		String response = params.get("SAMLResponse");
		assertNotNull(response);
		LogoutResponse lr = (LogoutResponse) transformer.fromXml(
			transformer.samlDecode(response, true),
			null,
			null
		);
		assertNotNull(lr);
		assertThat(lr.getStatus().getCode(), equalTo(StatusCode.SUCCESS));

	}

	@Test
	@DisplayName("SP receives logout response")
	void receiveLogoutResponse() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idp.getEntityId(),
			sp.getEntityId(),
			null,
			null
		);
		LogoutRequest request = helper.logoutRequest(
			idp,
			sp,
			assertion.getSubject().getPrincipal()
		);

		LogoutResponse response = helper.logoutResponse(request, sp, idp);

		String xml = transformer.toXml(response);
		String param = transformer.samlEncode(xml, true);

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		mockMvc.perform(
			get(location)
				.param("SAMLResponse", param)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andExpect(redirectedUrl("/saml/sp/select"))
		;
	}

	@Test
	@DisplayName("logout endpoint invoked when not authenticated")
	void notLoggedInLoggingOut() throws Exception {
		mockMvc.perform(
			get("/saml/sp/logout")
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andExpect(redirectedUrl("/saml/sp/select"))
		;
	}

	@Test
	@DisplayName("logout endpoint invoked with non SAML authentication")
	void nonSamlSessionLoggingOut() throws Exception {
		mockMvc.perform(
			get("/saml/sp/logout")
				.with(
					authentication(
						new UsernamePasswordAuthenticationToken("user", null, Collections.emptyList())
					)
				)
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andExpect(redirectedUrl("/saml/sp/select"))
		;
	}
}
