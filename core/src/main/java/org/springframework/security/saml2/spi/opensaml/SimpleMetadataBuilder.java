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

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.security.saml2.Namespace;
import org.springframework.security.saml2.init.SpringSecuritySaml;
import org.springframework.security.saml2.metadata.Binding;
import org.springframework.security.saml2.metadata.Endpoint;
import org.springframework.security.saml2.metadata.InvalidMetadataException;
import org.springframework.security.saml2.metadata.NameId;
import org.springframework.security.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml2.signature.DigestMethod;
import org.springframework.security.saml2.xml.SimpleKey;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.Element;

import static org.springframework.util.StringUtils.isEmpty;

public class SimpleMetadataBuilder {

    private boolean requestSigned = true;
    private boolean wantAssertionSigned = true;
    private boolean wantAuthnRequestsSigned = true;
    private String baseUrl;
    private String entityId = null;
    private String entityAlias = null;
    private String id;


    private List<SimpleKey> keys = new LinkedList<>();

    private SimpleKey signingKey = null;
    private AlgorithmMethod signatureAlgorithm = null;
    private DigestMethod signatureDigestMethod = null;


    private List<Endpoint> ssoEndpoints = new LinkedList<>();
    private List<Endpoint> logoutEndpoints = new LinkedList<>();
    private List<Endpoint> assertionEndpoints = new LinkedList<>();

    private Set<NameId> nameIds = new HashSet<>(
        Arrays.asList(
            NameId.EMAIL,
            NameId.TRANSIENT,
            NameId.PERSISTENT,
            NameId.UNSPECIFIED,
            NameId.X509_SUBJECT
        )
    );

    protected SimpleMetadataBuilder(String baseUrl) {
        if (isEmpty(baseUrl)) {
            throw new InvalidMetadataException("Invalid base URL for metadata:'" + baseUrl + "'");
        }

        try {
            URI uri = new URI(baseUrl);
            this.baseUrl = baseUrl;
            this.entityId = uri.toString();
            this.entityAlias = uri.getHost();
            this.id = uri.getHost();

        } catch (URISyntaxException e) {
            throw new InvalidMetadataException("Invalid base URL for metadata:'" + baseUrl + "'", e);
        }
    }

    public static SimpleMetadataBuilder builder(HttpServletRequest request) {
        return builder((String) null);
    }

    public static SimpleMetadataBuilder builder(String urlPrefix) {
        return new SimpleMetadataBuilder(urlPrefix);
    }

    public SimpleMetadataBuilder wantAssertionSigned(boolean wantAssertionSigned) {
        this.wantAssertionSigned = wantAssertionSigned;
        return this;
    }

    public SimpleMetadataBuilder requestSigned(boolean requestSigned) {
        this.requestSigned = requestSigned;
        return this;
    }

    public SimpleMetadataBuilder wantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
        this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
        return this;
    }

    public SimpleMetadataBuilder clearNameIDs() {
        nameIds.clear();
        return this;
    }

    public SimpleMetadataBuilder addNameID(NameId id) {
        nameIds.add(id);
        return this;
    }

    public SimpleMetadataBuilder addNameIDs(NameId... ids) {
        nameIds.addAll(Arrays.asList(ids));
        return this;
    }

    public SimpleMetadataBuilder addNameIDs(Collection<NameId> ids) {
        nameIds.addAll(ids);
        return this;
    }

    public SimpleMetadataBuilder removeNameID(NameId id) {
        nameIds.remove(id);
        return this;
    }

    public SimpleMetadataBuilder setEntityID(String id) {
        this.entityId = id;
        return this;
    }

    public SimpleMetadataBuilder setEntityAlias(String alias) {
        this.entityAlias = alias;
        return this;
    }

    public SimpleMetadataBuilder setId(String id) {
        this.id = id;
        return this;
    }

    public SimpleMetadataBuilder addKey(SimpleKey key) {
        this.keys.add(key);
        return this;
    }

    public SimpleMetadataBuilder addSigningKey(SimpleKey key,
                                               AlgorithmMethod signatureAlgorithm,
                                               DigestMethod signatureDigestMethod) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureDigestMethod = signatureDigestMethod;
        this.signingKey = key;
        return this;
    }

    public SimpleMetadataBuilder addSingleSignOnPath(String path, Binding binding) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
        builder.pathSegment(path);
        int index = ssoEndpoints.size();
        this.ssoEndpoints.add(
            new Endpoint()
                .setIndex(index)
                .setBinding(binding)
                .setLocation(builder.build().toUriString())
        );
        return this;
    }

    public SimpleMetadataBuilder addLogoutPath(String path, Binding binding) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
        builder.pathSegment(path);
        int index = logoutEndpoints.size();
        this.logoutEndpoints.add(
            new Endpoint()
                .setIndex(index)
                .setBinding(binding)
                .setLocation(builder.build().toUriString())
        );
        return this;
    }

    public SimpleMetadataBuilder addAssertionPath(String path, Binding binding, boolean isDefault) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
        builder.pathSegment(path);
        int index = assertionEndpoints.size();
        this.assertionEndpoints.add(
            new Endpoint()
                .setDefault(isDefault)
                .setIndex(index)
                .setBinding(binding)
                .setLocation(builder.build().toUriString())
        );
        return this;
    }


    public String buildServiceProviderMetadata() {
        if (isEmpty(entityId)) {
            throw new InvalidMetadataException("entityId is a required attribute for metadata");
        }

        OpenSamlConfiguration config = (OpenSamlConfiguration) SpringSecuritySaml.getInstance().init();
        EntityDescriptor entity = config.getEntityDescriptor();
        entity.setEntityID(entityId);
        entity.setID(id);

        SPSSODescriptor descriptor = config.getSPSSODescriptor();
        entity.getRoleDescriptors().add(descriptor);

        descriptor.setWantAssertionsSigned(wantAssertionSigned);
        descriptor.setAuthnRequestsSigned(requestSigned);
        descriptor.addSupportedProtocol(Namespace.NS_PROTOCOL);

        nameIds.forEach(n ->
                            descriptor.getNameIDFormats().add(config.getNameIDFormat(n))
        );

        if (!keys.isEmpty()) {
            descriptor.getKeyDescriptors().add(
                config.getKeyDescriptor(keys.get(0))
            );
        }


        for (int i = 0; i < assertionEndpoints.size(); i++) {
            Endpoint ep = assertionEndpoints.get(i);
            descriptor.getAssertionConsumerServices()
                .add(config.getAssertionConsumerService(ep, i));
        }

        for (int i = 0; i < logoutEndpoints.size(); i++) {
            Endpoint ep = logoutEndpoints.get(i);
            descriptor.getSingleLogoutServices()
                .add(config.getSingleLogoutService(ep));
        }

        try {
            if (signingKey != null) {
                config.signObject(entity, signingKey, signatureAlgorithm, signatureDigestMethod);
            }

            Element element = config
                .getMarshallerFactory()
                .getMarshaller(entity)
                .marshall(entity);
            return SerializeSupport.nodeToString(element);
        } catch (Exception e) {
            throw new InvalidMetadataException("Failed to create metadata", e);
        }
    }

    public String buildIdentityProviderMetadata() {
        if (isEmpty(entityId)) {
            throw new InvalidMetadataException("entityId is a required attribute for metadata");
        }

        OpenSamlConfiguration config = (OpenSamlConfiguration) SpringSecuritySaml.getInstance().init();
        EntityDescriptor entity = config.getEntityDescriptor();
        entity.setEntityID(entityId);
        entity.setID(id);

        IDPSSODescriptor descriptor = config.getIDPSSODescriptor();
        entity.getRoleDescriptors().add(descriptor);

        descriptor.setWantAuthnRequestsSigned(wantAuthnRequestsSigned);
        descriptor.addSupportedProtocol(Namespace.NS_PROTOCOL);

        nameIds.forEach(n ->
                            descriptor.getNameIDFormats().add(config.getNameIDFormat(n))
        );

        if (!keys.isEmpty()) {
            descriptor.getKeyDescriptors().add(
                config.getKeyDescriptor(keys.get(0))
            );
        }


        for (int i = 0; i < ssoEndpoints.size(); i++) {
            Endpoint ep = ssoEndpoints.get(i);
            descriptor.getSingleSignOnServices()
                .add(config.getSingleSignOnService(ep, i));
        }

        for (int i = 0; i < logoutEndpoints.size(); i++) {
            Endpoint ep = logoutEndpoints.get(i);
            descriptor.getSingleLogoutServices()
                .add(config.getSingleLogoutService(ep));
        }

        try {
            if (signingKey != null) {
                config.signObject(entity, signingKey, signatureAlgorithm, signatureDigestMethod);
            }

            Element element = config
                .getMarshallerFactory()
                .getMarshaller(entity)
                .marshall(entity);
            return SerializeSupport.nodeToString(element);
        } catch (Exception e) {
            throw new InvalidMetadataException("Failed to create metadata", e);
        }
    }


}
