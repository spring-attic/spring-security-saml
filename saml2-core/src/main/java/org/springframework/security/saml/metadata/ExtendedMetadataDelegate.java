/* Copyright 2011 Vladimir Schaefer
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
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

import java.util.Map;

/**
 * Class enables delegation of normal entity metadata loading to the selected provider while enhancing data with
 * extended metadata.
 */
public class ExtendedMetadataDelegate extends AbstractMetadataDelegate implements ExtendedMetadataProvider {

    /**
     * Metadata to use in case map doesn't contain any value.
     */
    private ExtendedMetadata defaultMetadata;

    /**
     * EntityID specific metadata.
     */
    private Map<String,ExtendedMetadata> extendedMetadataMap;

    /**
     * Uses provider for normal entity data, for each entity available in the delegate returns given defaults.
     *
     * @param delegate delegate with available entities
     * @param defaultMetadata default extended metadata, can be null
     */
    public ExtendedMetadataDelegate(MetadataProvider delegate, ExtendedMetadata defaultMetadata) {
        this(delegate, defaultMetadata, null);
    }

    /**
     * Uses provider for normal entity data, tries to locate extended metadata by search in the map.
     *
     * @param delegate delegate with available entities
     * @param extendedMetadataMap map, can be null
     */
    public ExtendedMetadataDelegate(MetadataProvider delegate, Map<String,ExtendedMetadata> extendedMetadataMap) {
        this(delegate, null, extendedMetadataMap);
    }

    /**
     * Uses provider for normal entity data, tries to locate extended metadata by search in the map, in case it's not found
     * uses the default.
     *
     * @param delegate delegate with available entities
     * @param defaultMetadata default extended metadata, can be null
     * @param extendedMetadataMap map, can be null
     */
    public ExtendedMetadataDelegate(MetadataProvider delegate, ExtendedMetadata defaultMetadata, Map<String,ExtendedMetadata> extendedMetadataMap) {
        super(delegate);
        this.defaultMetadata = defaultMetadata;
        this.extendedMetadataMap = extendedMetadataMap;
    }


    /**
     * Tries to load extended metadata for the given entity. The following algorithm is used:
     * <ol>
     * <li>Verifies that entityId can be located using the delegate (in other words makes sure we don't return extended metdata
     * for entities we don't have the basic ones for</li>
     * <li>In case extended metadata is available and contains value for the entityId it is returned</li>
     * <li>Returns default metadata otherwise</li>
     * </ol>
     *
     * @param entityID entity to load metadata for
     * @return extended metadata or null in case no default is given and entity can be located or is not present in the delegate
     * @throws MetadataProviderException error
     */
    public ExtendedMetadata getExtendedMetadata(String entityID) throws MetadataProviderException {

        EntityDescriptor entityDescriptor = getEntityDescriptor(entityID);
        if (entityDescriptor == null) {
            return null;
        }

        ExtendedMetadata extendedMetadata = null;

        if (extendedMetadataMap != null) {
            extendedMetadata = extendedMetadataMap.get(entityID);
        }

        if (extendedMetadata == null) {
            return defaultMetadata;
        } else {
            return extendedMetadata;
        }

    }

}