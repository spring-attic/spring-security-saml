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
import org.springframework.security.saml2.init.SpringSecuritySaml;
import org.springframework.security.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml2.xml.KeyType;
import org.springframework.security.saml2.xml.SimpleKey;

import static org.springframework.security.saml2.init.Defaults.identityProviderMetadata;
import static org.springframework.security.saml2.init.Defaults.serviceProviderMetadata;
import static org.springframework.security.saml2.init.SpringSecuritySaml.getInstance;
import static org.springframework.security.saml2.spi.ExamplePemKey.IDP_RSA_KEY;
import static org.springframework.security.saml2.spi.ExamplePemKey.SP_RSA_KEY;

public abstract class AuthenticationTests {
    SimpleKey spSigning;
    SimpleKey idpSigning;

    SimpleKey spVerifying;
    SimpleKey idpVerifying;

    String spBaseUrl;
    String idpBaseUrl;
    ServiceProviderMetadata serviceProviderMetadata;
    IdentityProviderMetadata identityProviderMetadata;

    SpringSecuritySaml config;

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
}
