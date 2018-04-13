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
import org.springframework.security.saml2.metadata.builder.EntityDescriptorBuilder;

import static org.springframework.util.StringUtils.isEmpty;

public class SimpleMetadataBuilder {

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
        private EntityDescriptorBuilder descriptor;

        protected SimpleMetadataBuilder(String baseUrl) {
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

        public static SimpleMetadataBuilder builder(HttpServletRequest request) {
            return builder((String)null);
        }

        public static SimpleMetadataBuilder builder(String urlPrefix) {
            return new SimpleMetadataBuilder(urlPrefix);
        }

        public SimpleMetadataBuilder wantAssertionSigned(boolean wantAssertionSigned) {
            this.wantAssertionSigned = wantAssertionSigned;
            return this;
        }

        public SimpleMetadataBuilder requestSigned(boolean requestSigned) {
            this.requestSigned =requestSigned;
            return this;
        }

        public SimpleMetadataBuilder clearNameIDs() {
            nameIDs.clear();
            return this;
        }

        public SimpleMetadataBuilder addNameID(NameID id) {
            nameIDs.add(id);
            return this;
        }

        public SimpleMetadataBuilder addNameIDs(NameID... ids) {
            nameIDs.addAll(Arrays.asList(ids));
            return this;
        }

        public SimpleMetadataBuilder addNameIDs(Collection<NameID> ids) {
            nameIDs.addAll(ids);
            return this;
        }

        public SimpleMetadataBuilder removeNameID(NameID id) {
            nameIDs.remove(id);
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


        public SimpleMetadataBuilder setEntityDescriptor(EntityDescriptorBuilder descriptor) {
            this.descriptor = descriptor;
            return this;
        }

        public ServiceProviderMetadata buildServiceProviderMetadata() {
            if (isEmpty(entityId)) {
                throw new InvalidMetadataException("entityId is a required attribute for metadata");
            }

            if (descriptor == null) {
                throw new InvalidMetadataException("EntityDescriptor can not be null");
            }


            throw new UnsupportedOperationException();
        }








    }
