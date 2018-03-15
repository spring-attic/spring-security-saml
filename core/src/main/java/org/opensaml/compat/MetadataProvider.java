/*
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
package org.opensaml.compat;


import javax.xml.namespace.QName;
import java.util.List;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;

/**
 * A local store into which metadata can be loaded and queried. Specific implementations may perform additional logic
 * such as caching (and refreshing) metadata and merging metadata, about a single entity, from multiple sources.
 *
 * <strong>NOTE</strong>, developers should not try to marshall the metadata that comes from a metadata provider. It is
 * possible that the a provider, or {@link MetadataFilter}, implementation may make changes to the retrieved metadata
 * that make it unusable for marshalling. For example, by removing elements required by the schema but not by the user
 * of the provider as a way of saving on memory.
 */
public interface MetadataProvider {

    /**
     * Gets whether the metadata returned by queries must be valid. At a minimum, metadata is valid only if the date
     * expressed in the element, and all its ancestral element's, validUntil attribute has not passed. Specific
     * implementations may add additional constraints.
     *
     * @return whether the metadata returned by queries must be valid
     */
    public boolean requireValidMetadata();

    /**
     * Sets whether the metadata returned by queries must be valid.
     *
     * @param requireValidMetadata whether the metadata returned by queries must be valid
     */
    public void setRequireValidMetadata(boolean requireValidMetadata);

    /**
     * Gets the metadata filter applied to the metadata.
     *
     * @return the metadata filter applied to the metadata
     */
    public MetadataFilter getMetadataFilter();

    /**
     * Sets the metadata filter applied to the metadata.
     *
     * @param newFilter the metadata filter applied to the metadata
     *
     * @throws MetadataProviderException thrown if the provider can not apply the filter to the metadata
     */
    public void setMetadataFilter(MetadataFilter newFilter) throws MetadataProviderException;

    /**
     * Gets the valid metadata tree, after the registered filter has been applied.
     *
     * @return the entire metadata tree
     *
     * @throws MetadataProviderException thrown if the provider can not fetch the metadata, must not be thrown simply if
     *             there is no metadata to fetch
     */
    public XMLObject getMetadata() throws MetadataProviderException;

    /**
     * Gets a valid named EntitiesDescriptor from the metadata.
     *
     * @param name the name of the EntitiesDescriptor
     *
     * @return the EntitiesDescriptor or null
     *
     * @throws MetadataProviderException thrown if the provider can not fetch the metadata, must not be thrown if there
     *             is simply no EntitiesDescriptor with the given name
     */
    public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException;

    /**
     * Gets the valid metadata for a given entity.
     *
     * @param entityID the ID of the entity
     *
     * @return the entity's metadata or null if there is no metadata or no valid metadata
     *
     * @throws MetadataProviderException thrown if the provider can not fetch the metadata, must not be thrown if there
     *             is simply no EntityDescriptor with the given ID
     */
    public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException;

    /**
     * Gets the valid role descriptors of a given type for a given entity.
     *
     * @param entityID the ID of the entity
     * @param roleName the role type
     *
     * @return the modifiable list of role descriptors
     *
     * @throws MetadataProviderException thrown if the provider can not fetch the metadata, must not be thrown if there
     *             is simply no such entity with the given roles
     */
    public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException;

    /**
     * Gets the valid role descriptors of a given type for a given entity that support the given protocol.
     *
     * @param entityID the ID of the entity
     * @param roleName the role type
     * @param supportedProtocol the protocol supported by the role
     *
     * @return the role descriptor
     *
     * @throws MetadataProviderException thrown if the provider can not fetch the metadata, must not be thrown if there
     *             is simply no such entity with the given role supporting the given protocol
     */
    public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol)
        throws MetadataProviderException;
}