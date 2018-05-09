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

package org.springframework.security.saml2.spi.opensaml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.springframework.security.saml2.metadata.Binding;
import org.springframework.security.saml2.metadata.Metadata;
import org.springframework.security.saml2.metadata.NameId;
import org.springframework.security.saml2.xml.KeyType;
import org.springframework.security.saml2.xml.SimpleKey;
import org.w3c.dom.Node;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.saml2.signature.AlgorithmMethod.RSA_SHA1;
import static org.springframework.security.saml2.signature.DigestMethod.SHA1;
import static org.springframework.security.saml2.spi.ExamplePemKey.RSA_TEST_KEY;
import static org.springframework.security.saml2.spi.opensaml.SimpleMetadataBuilder.builder;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml2.util.XmlTestUtil.getNodes;

public class SimpleMetadataBuilderTests {

    OpenSamlConfiguration config = (OpenSamlConfiguration) OpenSamlConfiguration.getInstance().init();

    @BeforeEach
    public void setup() throws Exception {
    }

    @Test
    public void getServiceProviderMetaData() {
        String baseUrl = "http://localhost:8080/uaa";
        String metadata = getSampleServiceProviderMetadata(baseUrl);

        assertNodeCount(metadata, "//md:EntityDescriptor", 1);
        Iterable<Node> nodes = getNodes(metadata, "//md:EntityDescriptor");
        assertNodeAttribute(nodes.iterator().next(), "ID", "localhost");
        assertNodeAttribute(nodes.iterator().next(), "entityID", "http://localhost:8080/uaa");

        assertNodeCount(metadata, "//md:SPSSODescriptor", 1);
        nodes = getNodes(metadata, "//md:SPSSODescriptor");
        assertNodeAttribute(nodes.iterator().next(), "AuthnRequestsSigned", "true");
        assertNodeAttribute(nodes.iterator().next(), "WantAssertionsSigned", "true");
        assertNodeAttribute(nodes.iterator().next(), "protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");


        assertNodeCount(metadata, "//ds:Signature", 1);
        assertNodeCount(metadata, "//ds:SignedInfo", 1);
        System.out.println("metadata:\n" + metadata);

    }

    @Test
    public void getIdentityProviderMetaData() {
        String baseUrl = "http://localhost:8080/uaa";
        String metadata = getSampleIdentityProviderMetadata(baseUrl);

        assertNodeCount(metadata, "//md:EntityDescriptor", 1);
        Iterable<Node> nodes = getNodes(metadata, "//md:EntityDescriptor");
        assertNodeAttribute(nodes.iterator().next(), "ID", "localhost");
        assertNodeAttribute(nodes.iterator().next(), "entityID", "http://localhost:8080/uaa");

        assertNodeCount(metadata, "//md:IDPSSODescriptor", 1);
        nodes = getNodes(metadata, "//md:IDPSSODescriptor");
        assertNodeAttribute(nodes.iterator().next(), "WantAuthnRequestsSigned", "true");
        assertNodeAttribute(nodes.iterator().next(), "protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");

        assertNodeCount(metadata, "//ds:Signature", 1);
        assertNodeCount(metadata, "//ds:SignedInfo", 1);
        System.out.println("metadata:\n" + metadata);

    }

    @Test
    public void readMetaDataToJavaObject() {
        String baseUrl = "http://localhost:8080/uaa";
        String xml = getSampleServiceProviderMetadata(baseUrl);
        Metadata metadata = (Metadata) config.resolve(xml, asList(RSA_TEST_KEY.getSimpleKey("signing-key")));
        assertNotNull(metadata);
        assertNotNull(metadata.getSsoProviders());
        assertEquals(1, metadata.getSsoProviders().size());
    }

    @Test
    public void readMetaDataAndValidateSignature() {
        String baseUrl = "http://localhost:8080/uaa";
        String metadata = getSampleServiceProviderMetadata(baseUrl);
        EntityDescriptor object = (EntityDescriptor) config.parse(metadata);
        config.validateSignature(object, asList(getPublicKey()));

        System.out.println("Entity Descriptor:" + object);
    }

    @Test
    public void readMetaDataAndExtractKeyAndValidateSignature() {
        String baseUrl = "http://localhost:8080/uaa";
        String metadata = getSampleServiceProviderMetadata(baseUrl);
        EntityDescriptor object = (EntityDescriptor) config.parse(metadata);

        X509Certificate certificate = object.getRoleDescriptors().get(0)
            .getKeyDescriptors().get(0)
            .getKeyInfo().getX509Datas().get(0)
            .getX509Certificates().get(0);
        String certValue = certificate.getValue();
        config.validateSignature(object, asList(getPublicKey(certValue)));
    }


    public String getSampleServiceProviderMetadata(String baseUrl) {
        return builder(baseUrl)
            .addKey(getDefaultKey())
            .addSigningKey(
                getDefaultKey(),
                RSA_SHA1,
                SHA1
            )
            .addAssertionPath("saml/SSO", Binding.POST, true)
            .addAssertionPath("saml/SSO", Binding.REDIRECT, false)
            .addLogoutPath("saml/SSO/logout", Binding.REDIRECT)
            .clearNameIDs()
            .addNameID(NameId.EMAIL)
            .addNameID(NameId.PERSISTENT)
            .wantAssertionSigned(true)
            .requestSigned(true)
            .buildServiceProviderMetadata();
    }

    public String getSampleIdentityProviderMetadata(String baseUrl) {
        return builder(baseUrl)
            .addKey(getDefaultKey())
            .addSigningKey(
                getDefaultKey(),
                RSA_SHA1,
                SHA1
            )
            .addSingleSignOnPath("saml/sp/SSO", Binding.POST)
            .addSingleSignOnPath("saml/sp/SSO", Binding.REDIRECT)
            .clearNameIDs()
            .addNameID(NameId.EMAIL)
            .addNameID(NameId.PERSISTENT)
            .addNameID(NameId.WIN_DOMAIN_QUALIFIED)
            .wantAuthnRequestsSigned(true)
            .buildIdentityProviderMetadata();
    }

    private SimpleKey getDefaultKey() {
        return new SimpleKey("alias", RSA_TEST_KEY.getPrivate(), RSA_TEST_KEY.getPublic(), RSA_TEST_KEY.getPassphrase(), KeyType.SIGNING);
    }

    private SimpleKey getPublicKey() {
        return getPublicKey(RSA_TEST_KEY.getPublic());
    }

    private SimpleKey getPublicKey(String cert) {
        return new SimpleKey("alias", null, cert, null, KeyType.SIGNING);
    }

}