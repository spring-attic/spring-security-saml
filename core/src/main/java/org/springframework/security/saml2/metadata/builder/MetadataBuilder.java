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

package org.springframework.security.saml2.metadata.builder;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.saml2.metadata.InvalidMetadataException;
import org.springframework.security.saml2.metadata.NameID;
import org.springframework.security.saml2.metadata.ServiceProviderMetadata;

import static org.springframework.util.StringUtils.isEmpty;

public class MetadataBuilder {

    private boolean requestSigned = true;
    private boolean wantAssertionSigned = true;
    private String entityId = null;
    private String baseUrl;
    private String entityAlias = null;
    private String id;

    private Set<NameID> nameIDs = new HashSet<>(
        Arrays.asList(
            NameID.EMAIL,
            NameID.TRANSIENT,
            NameID.PERSISTENT,
            NameID.UNSPECIFIED,
            NameID.X509_SUBJECT
        )
    );

    protected MetadataBuilder(String baseUrl) {
        if (isEmpty(baseUrl)) {
            throw new InvalidMetadataException("Invalid base URL for metadata:'"+baseUrl+"'");
        }
        try {
            new URI(baseUrl);
        } catch (URISyntaxException e) {
            throw new InvalidMetadataException("Invalid base URL for metadata:'"+baseUrl+"'", e);
        }
        this.baseUrl = baseUrl;
    }

    public static MetadataBuilder builder(HttpServletRequest request) {
        return builder((String)null);
    }

    public static MetadataBuilder builder(String urlPrefix) {
        return new MetadataBuilder(urlPrefix);
    }

    public MetadataBuilder wantAssertionSigned(boolean wantAssertionSigned) {
        this.wantAssertionSigned = wantAssertionSigned;
        return this;
    }

    public MetadataBuilder requestSigned(boolean requestSigned) {
        this.requestSigned =requestSigned;
        return this;
    }

    public MetadataBuilder clearNameIDs() {
        nameIDs.clear();
        return this;
    }

    public MetadataBuilder addNameID(NameID id) {
        nameIDs.add(id);
        return this;
    }

    public MetadataBuilder addNameIDs(NameID... ids) {
        nameIDs.addAll(Arrays.asList(ids));
        return this;
    }

    public MetadataBuilder addNameIDs(Collection<NameID> ids) {
        nameIDs.addAll(ids);
        return this;
    }

    public MetadataBuilder removeNameID(NameID id) {
        nameIDs.remove(id);
        return this;
    }

    public MetadataBuilder setEntityID(String id) {
        this.entityId = id;
        return this;
    }

    public MetadataBuilder setEntityAlias(String alias) {
        this.entityAlias = alias;
        return this;
    }

    public MetadataBuilder setId(String id) {
        this.id = id;
        return this;
    }


    public ServiceProviderMetadata buildServiceProviderMetadata() {
        if (isEmpty(entityId)) {
            throw new InvalidMetadataException("entityId is a required attribute for metadata");
        };
        throw new UnsupportedOperationException();
    }






}
