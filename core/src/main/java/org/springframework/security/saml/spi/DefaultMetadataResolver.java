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

package org.springframework.security.saml.spi;

import java.util.LinkedList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.config.LocalProviderConfiguration;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import static org.springframework.util.StringUtils.hasText;

public class DefaultMetadataResolver implements org.springframework.security.saml.MetadataResolver {

    private SamlServerConfiguration configuration;
    private Defaults defaults;
    private SamlTransformer transformer;

    @Autowired
    public void setTransformer(SamlTransformer transformer) {
        this.transformer = transformer;
    }

    @Autowired
    public DefaultMetadataResolver setSamlServerConfiguration(SamlServerConfiguration configuration) {
        this.configuration = configuration;
        return this;
    }

    @Autowired
    public DefaultMetadataResolver setDefaults(Defaults defaults) {
        this.defaults = defaults;
        return this;
    }

    @Override
    public ServiceProviderMetadata getLocalServiceProvider(String baseUrl) {
        LocalServiceProviderConfiguration sp = configuration.getServiceProvider();
        List<SimpleKey> keys = getSimpleKeys(sp);
        SimpleKey signing = sp.isSignMetadata() ? sp.getKeys().getActive().get(0) : null;
        ServiceProviderMetadata metadata = defaults.serviceProviderMetadata(baseUrl, keys, signing);
        if (hasText(sp.getEntityId())) {
            metadata.setEntityId(sp.getEntityId());
        }
        metadata.getServiceProvider().setWantAssertionsSigned(sp.isWantAssertionsSigned());
        metadata.getServiceProvider().setAuthnRequestsSigned(sp.isSignRequests());
        return metadata;
    }

    @Override
    public IdentityProviderMetadata getLocalIdentityProvider(String baseUrl) {
        LocalIdentityProviderConfiguration idp = configuration.getIdentityProvider();
        List<SimpleKey> keys = getSimpleKeys(idp);
        SimpleKey signing = idp.isSignMetadata() ? idp.getKeys().getActive().get(0) : null;
        IdentityProviderMetadata metadata = defaults.identityProviderMetadata(baseUrl, keys, signing);
        if (hasText(idp.getEntityId())) {
            metadata.setEntityId(idp.getEntityId());
        }
        metadata.getIdentityProvider().setWantAuthnRequestsSigned(idp.isWantRequestsSigned());
        return metadata;
    }

    @Override
    public IdentityProviderMetadata resolveIdentityProvider(Assertion assertion) {
        return null;
    }

    @Override
    public IdentityProviderMetadata resolveIdentityProvider(Response response) {
        return null;
    }

    @Override
    public IdentityProviderMetadata resolveIdentityProvider(String entityId) {
        return null;
    }

    @Override
    public ServiceProviderMetadata resolveServiceProvider(String entityId) {
        LocalIdentityProviderConfiguration idp = configuration.getIdentityProvider();
        for (ExternalProviderConfiguration c : idp.getProviders()) {
            String metadata = c.getMetadata();
            Metadata m = resolve(metadata);
            if (m instanceof ServiceProviderMetadata && entityId.equals(m.getEntityId())) {
                return (ServiceProviderMetadata) m;
            }
        }
        return null;
    }

    private Metadata resolve(String metadata) {
        return (Metadata) transformer.resolve(metadata, null);
    }

    @Override
    public ServiceProviderMetadata resolveServiceProvider(AuthenticationRequest request) {
        return null;
    }

    protected List<SimpleKey> getSimpleKeys(LocalProviderConfiguration sp) {
        List<SimpleKey> keys = new LinkedList<>();
        keys.addAll(sp.getKeys().getActive());
        keys.addAll(sp.getKeys().getStandBy());
        return keys;
    }

}
