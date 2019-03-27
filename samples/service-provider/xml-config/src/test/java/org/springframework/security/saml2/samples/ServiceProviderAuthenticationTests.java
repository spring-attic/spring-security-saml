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

import java.time.Clock;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml2.helper.SamlTestObjectHelper;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2ResponseSaml2;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.security.saml2.model.metadata.ServiceProviderMetadata;
import org.springframework.security.saml2.model.signature.Saml2AlgorithmMethod;
import org.springframework.security.saml2.model.signature.Saml2DigestMethod;
import org.springframework.security.saml2.serviceprovider.authentication.DefaultSamlAuthentication;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
	@ComponentScan(basePackages = "org/springframework/security/saml2/samples")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("response with signed assertion")
	void authenticate() throws Exception {
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		Saml2IdentityProviderMetadata idp =
			(Saml2IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Saml2Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			Saml2NameId.EMAIL
		);
		a.setSigningKey(
			SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData(),
			Saml2AlgorithmMethod.RSA_SHA256,
			Saml2DigestMethod.SHA256
		);
		Saml2ResponseSaml2 r = helper.response(null, a, sp, idp);
		String xml = transformer.toXml(r);
		String encoded = transformer.samlEncode(xml, false);

		mockMvc.perform(
			post("/saml/sp/SSO")
				.param("SAMLResponse", encoded)
		).andExpect(
			authenticated()
				.withAuthentication(authentication -> {
					assertTrue(authentication instanceof DefaultSamlAuthentication);
					assertNotNull(((DefaultSamlAuthentication) authentication).getResponseXml());
				})
		);
	}

	@Test
	@DisplayName("signed response")
	void authenticateWithOnlyResponseSigned() throws Exception {
		mockConfig(builder -> builder.wantAssertionsSigned(true));
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		Saml2IdentityProviderMetadata idp =
			(Saml2IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Saml2Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			Saml2NameId.EMAIL
		);
		Saml2ResponseSaml2 r = helper.response(null, a, sp, idp);
		r.setSigningKey(
			SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData(),
			Saml2AlgorithmMethod.RSA_SHA256,
			Saml2DigestMethod.SHA256
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
		Saml2IdentityProviderMetadata idp =
			(Saml2IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		SamlTestObjectHelper helper = new SamlTestObjectHelper(Clock.systemUTC());
		Saml2Assertion a = helper.assertion(
			sp,
			idp,
			null,
			"user@test.org",
			Saml2NameId.EMAIL
		);
		Saml2ResponseSaml2 r = helper.response(null, a, sp, idp);
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
		Saml2IdentityProviderMetadata idp =
			(Saml2IdentityProviderMetadata) transformer.fromXml(
				bootConfiguration.getServiceProvider().getProviders().get(0).getMetadata(),
				null,
				null
			);
		Saml2Assertion assertion = helper.assertion(sp, idp, null, "test-user@test.com", Saml2NameId.PERSISTENT);
		Saml2ResponseSaml2 response = helper.response(
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
