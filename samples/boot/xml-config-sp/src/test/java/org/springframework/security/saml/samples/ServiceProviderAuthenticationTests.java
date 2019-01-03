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
package org.springframework.security.saml.samples;

import java.time.Clock;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SAML Service Provider Authentication")
public class ServiceProviderAuthenticationTests extends AbstractServiceProviderTestBase {

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "org/springframework/security/saml/samples")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("response with signed assertion")
	void authenticate() throws Exception {
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			NameId.EMAIL
		);
		a.setSigningKey(
			SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData(),
			AlgorithmMethod.RSA_SHA256,
			DigestMethod.SHA256
		);
		Response r = helper.response(null, a, sp, idp);
		String xml = transformer.toXml(r);
		String encoded = transformer.samlEncode(xml, false);

		mockMvc.perform(
			post("/saml/sp/SSO")
				.param("SAMLResponse", encoded)
		).andExpect(authenticated());
	}

	@Test
	@DisplayName("signed response")
	void authenticateWithOnlyResponseSigned() throws Exception {
		mockConfig(builder -> builder.wantAssertionsSigned(true));
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			NameId.EMAIL
		);
		Response r = helper.response(null, a, sp, idp);
		r.setSigningKey(
			SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData(),
			AlgorithmMethod.RSA_SHA256,
			DigestMethod.SHA256
		);
		String xml = transformer.toXml(r);
		String encoded = transformer.samlEncode(xml, false);

		mockMvc.perform(
			post("/saml/sp/SSO")
				.param("SAMLResponse", encoded)
		).andExpect(authenticated());
	}

	@Test
	@DisplayName("signature not required")
	void authenticateNoSignature() throws Exception {
		mockConfig(builder -> builder.wantAssertionsSigned(false));
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			NameId.EMAIL
		);
		Response r = helper.response(null, a, sp, idp);
		String xml = transformer.toXml(r);
		String encoded = transformer.samlEncode(xml, false);

		mockMvc.perform(
			post("/saml/sp/SSO")
				.param("SAMLResponse", encoded)
		).andExpect(authenticated());
	}

	@Test
	@DisplayName("response with invalid destination")
	void invalidResponse() throws Exception {
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", NameId.PERSISTENT);
		Response response = helper.response(
			null,
			assertion,
			sp,
			idp
		);
		response.setDestination("invalid SP");

		String encoded = transformer.samlEncode(transformer.toXml(response), false);
		mockMvc.perform(
			post("/saml/sp/SSO/alias/boot-sample-sp")
				.param("SAMLResponse", encoded)
		)
			.andDo(print())
			.andExpect(status().isBadRequest())
			.andExpect(content().string(containsString("Destination mismatch: invalid SP")));
	}
}
