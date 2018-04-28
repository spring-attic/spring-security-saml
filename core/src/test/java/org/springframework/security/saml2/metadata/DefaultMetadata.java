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

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.security.saml2.xml.SimpleKey;

import static org.springframework.security.saml2.init.SpringSecuritySaml.getInstance;

public class DefaultMetadata {

    public static ServiceProviderMetadata getDefaultSPMetadata(String baseUrl,
                                                               List<SimpleKey> keys,
                                                               SimpleKey signingKey) {
        return new ServiceProviderMetadata()
            .setEntityId(baseUrl)
            .setId(UUID.randomUUID().toString())
            .setSigningKey(signingKey)
            .setKeys(keys)
            .setProviders(
                Arrays.asList(
                    new ServiceProvider()
                        .setWantAssertionsSigned(true)
                        .setAuthnRequestsSigned(signingKey!=null)
                        .setAssertionConsumerService(
                            Arrays.asList(
                                getInstance().init().getEndpoint(baseUrl,"/saml/sp/SSO", Binding.POST, 0, true),
                                getInstance().init().getEndpoint(baseUrl,"/saml/sp/SSO", Binding.REDIRECT, 1, false)
                            )
                        )
                        .setNameIDs(Arrays.asList(NameID.PERSISTENT,NameID.EMAIL))
                        .setKeys(keys)
                        .setSingleLogoutService(
                            Arrays.asList(
                                getInstance().init().getEndpoint(baseUrl,"/saml/sp/logout", Binding.REDIRECT, 0, true)
                            )
                        )
                )
            );
    }

    public static IdentityProviderMetadata getDefaultIDPMetadata(String baseUrl,
                                                                 List<SimpleKey> keys,
                                                                 SimpleKey signingKey) {
        return new IdentityProviderMetadata()
            .setEntityId(baseUrl)
            .setId(UUID.randomUUID().toString())
            .setSigningKey(signingKey)
            .setKeys(keys)
            .setProviders(
                Arrays.asList(
                    new IdentityProvider()
                        .setWantAuthnRequestsSigned(true)
                        .setSingleSignOnService(
                            Arrays.asList(
                                getInstance().init().getEndpoint(baseUrl,"/saml/idp/SSO", Binding.POST, 0, true),
                                getInstance().init().getEndpoint(baseUrl,"/saml/idp/SSO", Binding.REDIRECT, 1, false)
                            )
                        )
                        .setNameIDs(Arrays.asList(NameID.PERSISTENT,NameID.EMAIL))
                        .setKeys(keys)
                        .setSingleLogoutService(
                            Arrays.asList(
                                getInstance().init().getEndpoint(baseUrl,"/saml/idp/logout", Binding.REDIRECT, 0, true)
                            )
                        )
                )
            );

    }

}
