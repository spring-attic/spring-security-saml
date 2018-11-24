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

import java.net.URI;
import java.time.Clock;
import java.util.Map;
import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import sample.SimpleServiceProviderApplication.SampleSamlBootConfiguration;
import sample.proof_of_concept.ServiceProviderResolver;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.saml.helper.SamlTestObjectHelper.queryParams;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class ServiceProviderTests {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	SamlTransformer transformer;

	@SpyBean
	ServiceProviderResolver resolver;

	@Autowired
	SampleSamlBootConfiguration configuration;

	@BeforeEach
	void setUp() {
	}

	@AfterEach
	void reset() {
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("Home Page is Secure")
	void testHomePage() throws Exception {
		mockMvc.perform(
			get("/")

		)
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/saml/sp/select"))
		;
	}


	@Test
	@DisplayName("SP Initiated Login")
	void getAuthNRequest() throws Exception {
		AuthenticationRequest authn = getAuthenticationRequest();
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
	@DisplayName("SP Initiated Login - Do not Sign requests")
	void getAuthNRequestNotSigned() throws Exception {
		mockConfig(builder -> builder.withSignRequests(false));
		AuthenticationRequest authn = getAuthenticationRequest();
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

	@Test
	void authenticate() throws Exception {
		ServiceProviderMetadata sp = getServiceProviderMetadata();
		IdentityProviderMetadata idp =
			(IdentityProviderMetadata) transformer.fromXml(
				configuration.getServiceProvider().getProviders().get(0).getMetadata(),
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

	private AuthenticationRequest getAuthenticationRequest() throws Exception {
		MvcResult result = mockMvc.perform(
			get("/saml/sp/discovery")
				.param("idp", "http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php")
		)
			.andExpect(status().is3xxRedirection())
			.andReturn();

		String location = result.getResponse().getHeader("Location");
		Map<String, String> params = queryParams(new URI(location));
		String request = params.get("SAMLRequest");
		assertNotNull(request);
		String xml = transformer.samlDecode(request, true);
		Saml2Object saml2Object = transformer.fromXml(
			xml,
			configuration.getServiceProvider().getKeys().toList(),
			configuration.getServiceProvider().getKeys().toList()
		);
		assertNotNull(saml2Object);
		assertThat(saml2Object.getClass(), equalTo(AuthenticationRequest.class));
		return (AuthenticationRequest) saml2Object;
	}

	@Test
	@DisplayName("get Service Provider metadata")
	void testGetMetadata() throws Exception {
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("spring.security.saml.sp.id"));
	}

	@Test
	@DisplayName("Service Provider entity ID is generated")
	void generateSpEntityId() throws Exception {
		mockConfig(builder -> builder.withEntityId(null));
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("http://localhost"));
	}

	@Test
	@DisplayName("Service Provider entity ID is based on configured base path")
	void generateSpEntityIdFromBasePath() throws Exception {
		mockConfig(builder -> builder.withEntityId(null).withBasePath("http://some.other.host:8080/sample-sp"));
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("http://some.other.host:8080/sample-sp"));
		assertThat(metadata.getEntityAlias(), equalTo("some.other.host"));
	}

	private void mockConfig(Consumer<HostedServiceProviderConfiguration.Builder> modifier) {
		Mockito.doAnswer(
			invocation -> {
				HostedServiceProviderConfiguration config =
					(HostedServiceProviderConfiguration) invocation.callRealMethod();
				HostedServiceProviderConfiguration.Builder builder =
					HostedServiceProviderConfiguration.Builder.builder(config);
				modifier.accept(builder);
				return builder.build();
			}
		)
			.when(resolver).getConfiguration(ArgumentMatchers.any(HttpServletRequest.class));
	}

	private ServiceProviderMetadata getServiceProviderMetadata() throws Exception {
		String xml = mockMvc.perform(get("/saml/sp/metadata"))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertNotNull(xml);
		Metadata m = (Metadata) transformer.fromXml(xml, null, null);
		assertNotNull(m);
		assertThat(m.getClass(), equalTo(ServiceProviderMetadata.class));
		return (ServiceProviderMetadata) m;
	}
}
