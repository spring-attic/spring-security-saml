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

package org.springframework.security.samples;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(locations = {
	"classpath:application.yml",
	"classpath:single-logout-disabled.properties",
})
public class SingleLogoutDisabledBootTests {
	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private SamlTransformer transformer;

	@BeforeEach
	public void mockCache() {
	}

	@Test
	public void singleLogoutDisabledMetadata() throws Exception {
		IdentityProviderMetadata idpm = getIdentityProviderMetadata();
		assertThat(idpm.getIdentityProvider().getSingleLogoutService(), containsInAnyOrder());
	}

	protected IdentityProviderMetadata getIdentityProviderMetadata() throws Exception {
		MvcResult result = mockMvc.perform(get("/saml/idp/metadata"))
			.andExpect(status().isOk())
			.andReturn();
		String xml = result.getResponse().getContentAsString();
		Metadata m = (Metadata) transformer.fromXml(xml, null, null);
		assertNotNull(m);
		assertThat(m.getClass(), equalTo(IdentityProviderMetadata.class));
		return (IdentityProviderMetadata) m;
	}
}
