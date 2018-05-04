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

package org.springframework.security.saml2.metadata;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.init.SpringSecuritySaml;
import org.springframework.security.saml2.xml.KeyType;
import org.springframework.security.saml2.xml.SimpleKey;
import org.springframework.util.StreamUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml2.init.Defaults.identityProviderMetadata;
import static org.springframework.security.saml2.init.Defaults.serviceProviderMetadata;
import static org.springframework.security.saml2.init.SpringSecuritySaml.getInstance;
import static org.springframework.security.saml2.spi.ExamplePemKey.IDP_RSA_KEY;
import static org.springframework.security.saml2.spi.ExamplePemKey.SP_RSA_KEY;

public abstract class MetadataBase {

    protected SimpleKey spSigning;
    protected SimpleKey idpSigning;

    protected SimpleKey spVerifying;
    protected SimpleKey idpVerifying;

    protected String spBaseUrl;
    protected String idpBaseUrl;
    protected ServiceProviderMetadata serviceProviderMetadata;
    protected IdentityProviderMetadata identityProviderMetadata;

    protected SpringSecuritySaml config;

    @BeforeAll
    public static void init() {
        getInstance().init();
    }

    @BeforeEach
    public void setup() {
        config = getInstance();
        idpSigning = IDP_RSA_KEY.getSimpleKey("idp");
        idpVerifying = new SimpleKey("idp-verify", null, SP_RSA_KEY.getPublic(), null, KeyType.SIGNING);
        spSigning = SP_RSA_KEY.getSimpleKey("sp");
        spVerifying = new SimpleKey("sp-verify", null, IDP_RSA_KEY.getPublic(), null, KeyType.SIGNING);
        spBaseUrl = "http://sp.localhost:8080/uaa";
        idpBaseUrl = "http://idp.localhost:8080/uaa";
        serviceProviderMetadata = serviceProviderMetadata(
            spBaseUrl,
            Arrays.asList(spSigning),
            spSigning
        );
        identityProviderMetadata = identityProviderMetadata(
            idpBaseUrl,
            Arrays.asList(idpSigning),
            idpSigning
        );
    }

    protected byte[] getFileBytes(String path) throws IOException {
        ClassPathResource resource = new ClassPathResource(path);
        assertTrue(resource.exists(), path + " must exist.");
        return StreamUtils.copyToByteArray(resource.getInputStream());
    }
}
