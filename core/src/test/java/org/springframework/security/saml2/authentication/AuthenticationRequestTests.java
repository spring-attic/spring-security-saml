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

package org.springframework.security.saml2.authentication;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.init.SpringSecuritySaml;
import org.springframework.security.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml2.xml.SimpleKey;
import org.w3c.dom.Node;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.springframework.security.saml2.init.Defaults.authenticationRequest;
import static org.springframework.security.saml2.init.Defaults.identityProviderMetadata;
import static org.springframework.security.saml2.init.Defaults.serviceProviderMetadata;
import static org.springframework.security.saml2.spi.ExamplePemKey.RSA_TEST_KEY;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml2.util.XmlTestUtil.getNodes;
import static org.springframework.security.saml2.xml.KeyType.SIGNING;

class AuthenticationRequestTests {

    SimpleKey signing;

    @BeforeAll
    public static void init() {
        SpringSecuritySaml.getInstance().init();
    }

    @BeforeEach
    public void setup() {

        signing = new SimpleKey(
            "rsa",
            RSA_TEST_KEY.getPrivate(),
            RSA_TEST_KEY.getPublic(),
            RSA_TEST_KEY.getPassphrase(),
            SIGNING
        );
    }

    @Test
    public void create() throws Exception {
        String baseUrl = "http://localhost:8080/uaa";
        ServiceProviderMetadata sp = serviceProviderMetadata(
            baseUrl,
            Arrays.asList(signing),
            signing
        );
        IdentityProviderMetadata idp  = identityProviderMetadata(
            baseUrl,
            Arrays.asList(signing),
            signing
        );

        AuthenticationRequest request = authenticationRequest(sp, idp);
        String xml = SpringSecuritySaml.getInstance().toXml(request);

        assertNodeCount(xml, "//saml2p:AuthnRequest", 1);
        Iterable<Node> nodes = getNodes(xml, "//saml2p:AuthnRequest");
        assertNodeAttribute(nodes.iterator().next(), "Version", equalTo("2.0"));
        assertNodeAttribute(nodes.iterator().next(), "IssueInstant", notNullValue(String.class));
        assertNodeAttribute(nodes.iterator().next(), "ForceAuthn", equalTo("false"));
        assertNodeAttribute(nodes.iterator().next(), "IsPassive", equalTo("false"));
        assertNodeAttribute(nodes.iterator().next(), "ProtocolBinding", equalTo("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
        assertNodeAttribute(nodes.iterator().next(), "AssertionConsumerServiceURL", equalTo("http://localhost:8080/uaa/saml/sp/SSO"));


    }
}