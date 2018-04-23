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

package org.springframework.security.saml2.metadata.builder.opensaml;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.springframework.security.saml2.init.OpenSamlConfiguration;
import org.springframework.security.saml2.metadata.Binding;
import org.springframework.security.saml2.metadata.Metadata;
import org.springframework.security.saml2.metadata.NameID;
import org.springframework.security.saml2.xml.KeyType;
import org.springframework.security.saml2.xml.SimpleKey;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.saml2.signature.AlgorithmMethod.RSA_SHA1;
import static org.springframework.security.saml2.signature.DigestMethod.SHA1;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml2.util.XmlTestUtil.getNodes;

public class SimpleMetadataBuilderTests {

    OpenSamlConfiguration config = (OpenSamlConfiguration) OpenSamlConfiguration.getInstance().init();

    @BeforeEach
    public void setup() throws Exception {
    }

    @Test
    public void getMetaData() {
        String baseUrl = "http://localhost:8080/uaa";
        String metadata = getSampleMetadata(baseUrl);

        assertNodeCount(metadata, "//md:EntityDescriptor", 1);
        Iterable<Node> nodes = getNodes(metadata, "//md:EntityDescriptor");
        assertNodeAttribute(nodes.iterator().next(), "ID", "localhost");
        assertNodeAttribute(nodes.iterator().next(), "entityID", "http://localhost:8080/uaa");

        assertNodeCount(metadata, "//ds:Signature", 1);
        assertNodeCount(metadata, "//ds:SignedInfo", 1);
        System.out.println("metadata:\n"+metadata);

    }

    @Test
    public void readMetaDataToJavaObject() {
        String baseUrl = "http://localhost:8080/uaa";
        String xml = getSampleMetadata(baseUrl);
        Metadata metadata = config.resolveMetadata(xml, null);
        assertNotNull(metadata);
        assertNotNull(metadata.getSsoProviders());
        assertEquals(1, metadata.getSsoProviders().size());
    }

    @Test
    public void readMetaDataAndValidateSignature() {
        String baseUrl = "http://localhost:8080/uaa";
        String metadata = getSampleMetadata(baseUrl);
        EntityDescriptor object = (EntityDescriptor) config.parse(metadata);
        config.validateSignature(object, Arrays.asList(getPublicKey()));

        System.out.println("Entity Descriptor:"+object);
    }

    @Test
    public void readMetaDataAndExtractKeyAndValidateSignature() {
        String baseUrl = "http://localhost:8080/uaa";
        String metadata = getSampleMetadata(baseUrl);
        EntityDescriptor object = (EntityDescriptor) config.parse(metadata);

        X509Certificate certificate = object.getRoleDescriptors().get(0)
            .getKeyDescriptors().get(0)
            .getKeyInfo().getX509Datas().get(0)
            .getX509Certificates().get(0);
        String certValue = certificate.getValue();
        config.validateSignature(object, Arrays.asList(getPublicKey(certValue)));
    }


    public String getSampleMetadata(String baseUrl) {
        return new SimpleMetadataBuilder(baseUrl)
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
                .addNameID(NameID.EMAIL)
                .addNameID(NameID.PERSISTENT)
                .wantAssertionSigned(true)
                .requestSigned(true)
                .buildServiceProviderMetadata();
    }

    private SimpleKey getDefaultKey() {
        return new SimpleKey("alias", SIGNING_KEY, SIGNING_CERT, SIGNING_KEY_PASSPHRASE, KeyType.SIGNING);
    }

    private SimpleKey getPublicKey() {
        return getPublicKey(SIGNING_CERT);
    }
    private SimpleKey getPublicKey(String cert) {
        return new SimpleKey("alias", null, cert, null, KeyType.SIGNING);
    }

    public static final String SIGNING_KEY_PASSPHRASE = "password";

    public static final String SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
        "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
        "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
        "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
        "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
        "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
        "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
        "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
        "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
        "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
        "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
        "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
        "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
        "-----END RSA PRIVATE KEY-----";

    public static final String SIGNING_CERT = "-----BEGIN CERTIFICATE-----\n" +
        "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
        "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
        "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
        "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
        "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
        "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
        "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
        "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
        "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
        "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
        "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
        "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
        "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
        "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
        "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
        "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
        "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
        "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
        "-----END CERTIFICATE-----";
}