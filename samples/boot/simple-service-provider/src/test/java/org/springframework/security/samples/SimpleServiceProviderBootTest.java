/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.samples;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SimpleServiceProviderBootTest {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private SamlTransformer transformer;
    @Autowired
    SamlServerConfiguration configuration;

    @Test
    public void checkConfig() throws Exception {
        assertNotNull(configuration);
        assertNull(configuration.getIdentityProvider());
        LocalServiceProviderConfiguration sp = configuration.getServiceProvider();
        assertNotNull(sp);
        assertThat(sp.getEntityId(), equalTo("test-sp-entity-id"));
        assertTrue(sp.isSignMetadata());
        assertTrue(sp.isSignRequests());
        List<SimpleKey> activeKeys = sp.getKeys().getActive();
        assertNotNull(activeKeys);
        assertThat(activeKeys.size(), equalTo(1));
        List<SimpleKey> standByKeys = sp.getKeys().getStandBy();
        assertNotNull(standByKeys);
        assertThat(standByKeys.size(), equalTo(2));
    }

    @Test
    public void getServiceProviderMetadata() throws Exception {
        String xml = mockMvc.perform(get("/saml/sp/metadata"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
        assertNotNull(xml);
        Metadata m = (Metadata) transformer.resolve(xml, null);
        assertNotNull(m);
        assertThat(m.getClass(), equalTo(ServiceProviderMetadata.class));
    }


    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(basePackages = "sample")
    public static class SpringBootApplicationTestConfig {
    }
}
