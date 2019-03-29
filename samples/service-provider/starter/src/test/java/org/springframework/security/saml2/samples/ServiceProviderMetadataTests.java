/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.saml2.samples;

import java.time.Clock;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.model.metadata.Saml2Metadata;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProviderMetadata;
import org.springframework.security.saml2.spi.keycloak.KeycloakSaml2Implementation;
import org.springframework.security.saml2.spi.keycloak.KeycloakSaml2Transformer;
import org.springframework.security.saml2.spi.opensaml.OpenSaml2Implementation;
import org.springframework.security.saml2.spi.opensaml.OpenSaml2Transformer;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SAML Service Provider Metadata")
public class ServiceProviderMetadataTests  {

	@Autowired
	MockMvc mockMvc;

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "org/springframework/security/saml2/samples")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	@DisplayName("fetch of SP metadata - decode using OpenSAML")
	void fetchMetadataOpenSaml() throws Exception {
		Saml2ServiceProviderMetadata spm = getServiceProviderMetadata(new OpenSaml2Transformer(
			new OpenSaml2Implementation(Clock.systemUTC()).init()
		));
		assertNotNull(spm);
	}

	@Test
	@DisplayName("fetch of SP metadata - decode using Keycloak")
	void fetchMetadataKeycloak() throws Exception {
		Saml2ServiceProviderMetadata spm = getServiceProviderMetadata(new KeycloakSaml2Transformer(
			new KeycloakSaml2Implementation(Clock.systemUTC()).init()
		));
		assertNotNull(spm);
	}

	Saml2ServiceProviderMetadata getServiceProviderMetadata(Saml2Transformer transformer) throws Exception {
		String xml = mockMvc.perform(get("/saml/sp/metadata"))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertNotNull(xml);
		Saml2Metadata m = (Saml2Metadata) transformer.fromXml(xml, null, null);
		assertNotNull(m);
		assertThat(m.getClass(), equalTo(Saml2ServiceProviderMetadata.class));
		return (Saml2ServiceProviderMetadata) m;
	}

}
