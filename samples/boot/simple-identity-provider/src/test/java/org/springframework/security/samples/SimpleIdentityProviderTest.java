/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.springframework.security.samples;

import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SimpleIdentityProviderTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SamlTransformer transformer;

    @Test
    public void getIdentityProviderMetadata() throws Exception {
        MvcResult result = mockMvc.perform(get("/saml/idp/metadata"))
            .andExpect(status().isOk())
            .andReturn();
        String xml = result.getResponse().getContentAsString();
        Metadata m = (Metadata) transformer.resolve(xml, null);
        assertNotNull(m);
        assertThat(m.getClass(), equalTo(IdentityProviderMetadata.class));
    }

    @Test
    public void idpInitiatedLogin() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", null, Collections.emptyList());
        MvcResult result = mockMvc.perform(
            get("/saml/idp/init")
                .param("sp", "test-sp-entity-id")
            .with(authentication(token))
        )
            .andExpect(status().isOk())
            .andReturn();
        String html = result.getResponse().getContentAsString();
        assertThat(html, containsString("name=\"SAMLResponse\""));
        String response = extractResponse(html, "SAMLResponse");
        Response r = (Response) transformer.resolve(transformer.samlDecode(response), null);
        assertNotNull(r);
        assertThat(r.getAssertions(), notNullValue());
        assertThat(r.getAssertions().size(), equalTo(1));
    }

    private String extractResponse(String html, String name) {
        Pattern p = Pattern.compile(" name=\"(.*?)\" value=\"(.*?)\"" );
        Matcher m = p.matcher(html);
        while ( m.find() ) {
            String pname = m.group(1);
            String value = m.group(2);
            if (name.equals(pname)) {
                return value;
            }
        }
        return null;
    }


    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(basePackages = "sample")
    public static class SpringBootApplicationTestConfig {
    }
}
