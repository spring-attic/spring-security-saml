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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import sample.proof_of_concept.StaticServiceProviderResolver;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SimpleServiceProviderBootTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	SamlTransformer transformer;

	@SpyBean
	StaticServiceProviderResolver resolver;

	@BeforeEach
	void setUp() {
	}

	@AfterEach
	public void reset() {
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("get Service Provider metadata")
	public void testGetMetadata() throws Exception {
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("spring.security.saml.sp.id"));
	}

	@Test
	@DisplayName("Service Provider entity ID is generated")
	public void generateSpEntityId() throws Exception {
		Mockito.doAnswer(
			invocation -> {
				HostedServiceProviderConfiguration config =
					(HostedServiceProviderConfiguration) invocation.callRealMethod();
				return HostedServiceProviderConfiguration.Builder.builder(config)
					.withEntityId(null)
					.build();
			}
		)
			.when(resolver).getConfiguration();
		ServiceProviderMetadata metadata = getServiceProviderMetadata();
		assertNotNull(metadata);
		assertThat(metadata.getEntityId(), equalTo("http://localhost:8080/sample-sp"));
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
