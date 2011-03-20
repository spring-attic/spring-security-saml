/* Copyright 2009 Vladimir Sch�fer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.metadata;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;

/**
 * Class implements simple metadata provider which retrieves EntityDescriptor from preconfigured object.
 *
 * @author Vladimir Sch�fer
 */
public class MetadataMemoryProvider extends AbstractMetadataProvider {

    /**
     * Preconfigured descriptor
     */
    private EntityDescriptor descriptor;

    /**
     * Constructor settings descriptor in parameter as the only entity available from this provider.
     *
     * @param descriptor descriptor to use
     */
    public MetadataMemoryProvider(EntityDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    /**
     * @return preconfigured entity descriptor
     */
    public XMLObject getMetadata() {
        return descriptor;
    }

    @Override
    protected XMLObject doGetMetadata() throws MetadataProviderException {
        return descriptor;
    }

}
