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

package org.springframework.security.saml.saml2.metadata;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml.MetadataResolver;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.spi.DefaultMetadataResolver;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.Defaults;
import org.springframework.security.saml.spi.opensaml.OpenSamlConfiguration;
import org.springframework.util.StreamUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.spi.ExamplePemKey.IDP_RSA_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.SP_RSA_KEY;

public abstract class MetadataBase {

    protected SimpleKey spSigning;
    protected SimpleKey idpSigning;

    protected SimpleKey spVerifying;
    protected SimpleKey idpVerifying;

    protected String spBaseUrl;
    protected String idpBaseUrl;
    protected ServiceProviderMetadata serviceProviderMetadata;
    protected IdentityProviderMetadata identityProviderMetadata;

    protected static SamlTransformer config;
    protected static MetadataResolver resolver;
    protected static Defaults defaults;

    @BeforeAll
    public static void init() throws Exception {
        config = new DefaultSamlTransformer(new OpenSamlConfiguration());
        resolver = new DefaultMetadataResolver();
        defaults = new Defaults();
        ((DefaultSamlTransformer) config).afterPropertiesSet();
    }

    @BeforeEach
    public void setup() {
        idpSigning = IDP_RSA_KEY.getSimpleKey("idp");
        idpVerifying = new SimpleKey("idp-verify", null, SP_RSA_KEY.getPublic(), null, KeyType.SIGNING);
        spSigning = SP_RSA_KEY.getSimpleKey("sp");
        spVerifying = new SimpleKey("sp-verify", null, IDP_RSA_KEY.getPublic(), null, KeyType.SIGNING);
        spBaseUrl = "http://sp.localhost:8080/uaa";
        idpBaseUrl = "http://idp.localhost:8080/uaa";
        serviceProviderMetadata = defaults.serviceProviderMetadata(
            spBaseUrl,
            Arrays.asList(spSigning),
            spSigning
        );
        identityProviderMetadata = defaults.identityProviderMetadata(
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
