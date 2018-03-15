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
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

/** An abstract, base, implementation of a metadata provider. */
public abstract class AbstractMetadataProvider extends BaseMetadataProvider {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractMetadataProvider.class);

    /** Whether the metadata provider has been initialized. */
    private boolean initialized;

    /**
     * Whether problems during initialization should cause the provider to fail or go on without metadata. The
     * assumption being that in most cases a provider will recover at some point in the future. Default: true.
     */
    private boolean failFastInitialization;

    /** Cache of entity IDs to their descriptors. */
    private Map<String, EntityDescriptor> indexedDescriptors;

    /** Pool of parsers used to process XML. */
    private ParserPool parser;

    /** Constructor. */
    public AbstractMetadataProvider() {
        super();
        indexedDescriptors = new ConcurrentHashMap<String, EntityDescriptor>();
        failFastInitialization = true;
        initialized = false;
    }

    /** {@inheritDoc} */
    public XMLObject getMetadata() throws MetadataProviderException {
        if (!isInitialized()) {
            throw new MetadataProviderException("Metadata provider has not been initialized");
        }

        XMLObject metadata = doGetMetadata();

        if (metadata == null) {
            log.debug("Metadata provider does not currently contain any metadata");
        }

        if (!isValid(metadata)) {
            log.debug("Metadata document exists, but it is no longer valid");
            return null;
        }

        return metadata;
    }

    /**
     * Gets the metadata currently held by the provider. This method should not check if the provider is initialized, if
     * the metadata is valid, etc. All of this is done by the invoker of this method.
     *
     * @return the metadata currently held by this provider or null if no metadata is available
     *
     * @throws MetadataProviderException thrown if there is a problem retrieving the metadata
     */
    protected abstract XMLObject doGetMetadata() throws MetadataProviderException;

    /** {@inheritDoc} */
    public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {
        if (!isInitialized()) {
            throw new MetadataProviderException("Metadata provider has not been initialized");
        }

        if (DataTypeHelper.isEmpty(name)) {
            log.debug("EntitiesDescriptor name was null or empty, skipping search for it");
            return null;
        }

        EntitiesDescriptor descriptor = doGetEntitiesDescriptor(name);
        if (descriptor == null) {
            log.debug("Metadata document does not contain an EntitiesDescriptor with the name {}", name);
            return null;
        } else if (!isValid(descriptor)) {
            log.debug("Metadata document contained an EntitiesDescriptor with the name {}, but it was no longer valid",
                      name);
            return null;
        }

        return descriptor;
    }

    /**
     * Gets the named EntitiesDescriptor from the metadata. This method should not check if the provider is initialized,
     * if arguments are null, if metadata is valid, etc. All of this is done by the invoker of this method.
     *
     * @param name the name of the EntitiesDescriptor, never null
     *
     * @return the named EntitiesDescriptor or null if no such EntitiesDescriptor exists
     *
     * @throws MetadataProviderException thrown if there is a problem searching for the EntitiesDescriptor
     */
    protected EntitiesDescriptor doGetEntitiesDescriptor(String name) throws MetadataProviderException {
        XMLObject metadata = doGetMetadata();
        if (metadata == null) {
            log.debug("Metadata provider does not currently contain any metadata, unable to look for an EntitiesDescriptor with the name {}",
                      name);
            return null;
        }

        EntitiesDescriptor descriptor = null;
        if (metadata instanceof EntitiesDescriptor) {
            descriptor = getEntitiesDescriptorByName(name, (EntitiesDescriptor) metadata);
        }

        return descriptor;
    }

    /** {@inheritDoc} */
    public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException {
        if (!isInitialized()) {
            throw new MetadataProviderException("Metadata provider has not been initialized");
        }

        if (DataTypeHelper.isEmpty(entityID)) {
            log.debug("EntityDescriptor entityID was null or empty, skipping search for it");
            return null;
        }

        EntityDescriptor descriptor = doGetEntityDescriptor(entityID);
        if (descriptor == null) {
            log.debug("Metadata document does not contain an EntityDescriptor with the ID {}", entityID);
            return null;
        } else if (!isValid(descriptor)) {
            log.debug("Metadata document contained an EntityDescriptor with the ID {}, but it was no longer valid",
                      entityID);
            return null;
        }

        return descriptor;
    }

    /**
     * Gets the identified EntityDescriptor from the metadata. This method should not check if the provider is
     * initialized, if arguments are null, if the metadata is valid, etc. All of this is done by the invoker of this
     * method.
     *
     * @param entityID ID of the EntityDescriptor, never null
     *
     * @return the identified EntityDescriptor or null if no such EntityDescriptor exists
     *
     * @throws MetadataProviderException thrown if there is a problem searching for the EntityDescriptor
     */
    protected EntityDescriptor doGetEntityDescriptor(String entityID) throws MetadataProviderException {
        XMLObject metadata = doGetMetadata();
        if (metadata == null) {
            log.debug("Metadata document was empty, unable to look for an EntityDescriptor with the ID {}", entityID);
            return null;
        }

        return getEntityDescriptorById(entityID, metadata);
    }

    /** {@inheritDoc} */
    public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {
        if (!isInitialized()) {
            throw new MetadataProviderException("Metadata provider has not been initialized");
        }

        if (DataTypeHelper.isEmpty(entityID)) {
            log.debug("EntityDescriptor entityID was null or empty, skipping search for roles");
            return null;
        }

        if (roleName == null) {
            log.debug("Role descriptor name was null, skipping search for roles");
            return null;
        }

        List<RoleDescriptor> roleDescriptors = doGetRole(entityID, roleName);
        if (roleDescriptors == null || roleDescriptors.isEmpty()) {
            log.debug("Entity descriptor {} did not contain any {} roles", entityID, roleName);
            return null;
        }

        Iterator<RoleDescriptor> roleDescItr = roleDescriptors.iterator();
        while (roleDescItr.hasNext()) {
            if (!isValid(roleDescItr.next())) {
                log.debug("Metadata document contained a role of type {} for entity {}, but it was invalid", roleName,
                          entityID);
                roleDescItr.remove();
            }
        }

        if (roleDescriptors.isEmpty()) {
            log.debug("Entity descriptor {} did not contain any valid {} roles", entityID, roleName);
        }
        return roleDescriptors;
    }

    /**
     * Gets the identified roles from an EntityDescriptor. This method should not check if the provider is initialized,
     * if arguments are null, if the roles are valid, etc. All of this is done by the invoker of this method.
     *
     * @param entityID ID of the entity from which to retrieve the roles, never null
     * @param roleName name of the roles to search for, never null
     *
     * @return the modifiable list of identified roles or an empty list if no roles exists
     *
     * @throws MetadataProviderException thrown if there is a problem searching for the roles
     */
    protected List<RoleDescriptor> doGetRole(String entityID, QName roleName) throws MetadataProviderException {
        EntityDescriptor entity = doGetEntityDescriptor(entityID);
        if (entity == null) {
            log.debug("Metadata document did not contain a descriptor for entity {}", entityID);
            return Collections.emptyList();
        }

        List<RoleDescriptor> descriptors = entity.getRoleDescriptors(roleName);
        if (descriptors != null && !descriptors.isEmpty()) {
            return new ArrayList<RoleDescriptor>(descriptors);
        }

        return Collections.emptyList();
    }

    /** {@inheritDoc} */
    public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol)
        throws MetadataProviderException {
        if (!isInitialized()) {
            throw new MetadataProviderException("Metadata provider has not been initialized");
        }

        if (DataTypeHelper.isEmpty(entityID)) {
            log.debug("EntityDescriptor entityID was null or empty, skipping search for role");
            return null;
        }

        if (roleName == null) {
            log.debug("Role descriptor name was null, skipping search for role");
            return null;
        }

        if (DataTypeHelper.isEmpty(supportedProtocol)) {
            log.debug("Supported protocol was null, skipping search for role.");
            return null;
        }

        RoleDescriptor role = doGetRole(entityID, roleName, supportedProtocol);
        if (role == null) {
            log.debug("Metadata document does not contain a role of type {} supporting protocol {} for entity {}",
                      new Object[] { roleName, supportedProtocol, entityID });
            return null;
        }

        if (!isValid(role)) {
            log
                .debug(
                    "Metadata document contained a role of type {} supporting protocol {} for entity {}, but it was not longer valid",
                    new Object[] { roleName, supportedProtocol, entityID });
            return null;
        }

        return role;
    }

    /**
     * Gets the role which supports the given protocol.
     *
     * @param entityID ID of the entity from which to retrieve roles, never null
     * @param roleName name of the role to search for, never null
     * @param supportedProtocol protocol to search for, never null
     *
     * @return the role supporting the protocol or null if no such role exists
     *
     * @throws MetadataProviderException thrown if there is a problem search for the roles
     */
    protected RoleDescriptor doGetRole(String entityID, QName roleName, String supportedProtocol)
        throws MetadataProviderException {
        List<RoleDescriptor> roles = doGetRole(entityID, roleName);
        if (roles == null || roles.isEmpty()) {
            log.debug("Metadata document did not contain any role descriptors of type {} for entity {}", roleName,
                      entityID);
            return null;
        }

        Iterator<RoleDescriptor> rolesItr = roles.iterator();
        RoleDescriptor role = null;
        while (rolesItr.hasNext()) {
            role = rolesItr.next();
            if (role != null && role.isSupportedProtocol(supportedProtocol)) {
                return role;
            }
        }

        return null;
    }

    /**
     * Gets whether this provider is initialized.
     *
     * @return whether this provider is initialized
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Sets whether this provider is initialized.
     *
     * @param isInitialized whether this provider is initialized
     */
    protected void setInitialized(boolean isInitialized) {
        initialized = isInitialized;
    }

    /**
     * Gets whether problems during initialization should cause the provider to fail or go on without metadata. The
     * assumption being that in most cases a provider will recover at some point in the future.
     *
     * @return whether problems during initialization should cause the provider to fail
     */
    public boolean isFailFastInitialization() {
        return failFastInitialization;
    }

    /**
     * Sets whether problems during initialization should cause the provider to fail or go on without metadata. The
     * assumption being that in most cases a provider will recover at some point in the future.
     *
     * @param failFast whether problems during initialization should cause the provider to fail
     */
    public void setFailFastInitialization(boolean failFast) {
        if (isInitialized()) {
            return;
        }

        failFastInitialization = failFast;
    }

    /**
     * Gets the pool of parsers to use to parse XML.
     *
     * @return pool of parsers to use to parse XML
     */
    public ParserPool getParserPool() {
        return parser;
    }

    /**
     * Sets the pool of parsers to use to parse XML.
     *
     * @param pool pool of parsers to use to parse XML
     */
    public void setParserPool(ParserPool pool) {
        parser = pool;
    }

    /**
     * Initializes this metadata provider. If called after the metadata provider has already been initialized this
     * method simply returns.
     *
     * @throws MetadataProviderException thrown if there is a problem initializing the problem and fail fast
     *             Initialization is enabled
     */
    public synchronized void initialize() throws MetadataProviderException {
        if (initialized) {
            return;
        }

        try {
            doInitialization();
            initialized = true;
        } catch (MetadataProviderException e) {
            if (failFastInitialization) {
                log.error("Metadata provider failed to properly initialize, fail-fast=true, halting", e);
                throw e;
            } else {
                log.error("Metadata provider failed to properly initialize, fail-fast=false, "
                              + "continuing on in a degraded state", e);
                initialized = true;
            }
        }
    }

    /** {@inheritDoc} */
    public synchronized void destroy() {
        initialized = false;
        indexedDescriptors = Collections.emptyMap();
        parser = null;

        super.destroy();
    }

    /**
     * Subclasses should override this method to perform any initialization logic necessary. Default implementation is a
     * no-op.
     *
     * @throws MetadataProviderException thrown if there is a problem initializing the provider
     */
    protected void doInitialization() throws MetadataProviderException {

    }

    /**
     * Clears the entity ID to entity descriptor index.
     */
    protected void clearDescriptorIndex() {
        indexedDescriptors.clear();
    }

    /**
     * Unmarshalls the metadata from the given stream. The stream is closed by this method and the returned metadata
     * released its DOM representation.
     *
     * @param metadataInput the input reader to the metadata.
     *
     * @return the unmarshalled metadata
     *
     * @throws UnmarshallingException thrown if the metadata can no be unmarshalled
     */
    protected XMLObject unmarshallMetadata(InputStream metadataInput) throws UnmarshallingException {
        try {
            log.trace("Parsing retrieved metadata into a DOM object");
            Document mdDocument = parser.parse(metadataInput);

            log.trace("Unmarshalling and caching metdata DOM");
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(mdDocument.getDocumentElement());
            if (unmarshaller == null) {
                String msg ="No unmarshaller registered for document element " + XMLHelper
                    .getNodeQName(mdDocument.getDocumentElement());
                log.error(msg);
                throw new UnmarshallingException(msg);
            }
            XMLObject metadata = unmarshaller.unmarshall(mdDocument.getDocumentElement());
            return metadata;
        } catch (Exception e) {
            throw new UnmarshallingException(e);
        } finally {
            try {
                metadataInput.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    /**
     * Filters the given metadata.
     *
     * @param metadata the metadata to be filtered
     *
     * @throws FilterException thrown if there is an error filtering the metadata
     */
    protected void filterMetadata(XMLObject metadata) throws FilterException {
        if (getMetadataFilter() != null) {
            log.debug("Applying metadata filter");
            getMetadataFilter().filter(metadata);
        }
    }

    /**
     * Releases the DOM representation from the metadata object.
     *
     * @param metadata the metadata object
     */
    protected void releaseMetadataDOM(XMLObject metadata) {
        if (metadata != null) {
            metadata.releaseDOM();
            metadata.releaseChildrenDOM(true);
        }
    }

    /**
     * Gets the EntityDescriptor with the given ID from the cached metadata.
     *
     * @param entityID the ID of the entity to get the descriptor for
     * @param metadata metadata associated with the entity
     *
     * @return the EntityDescriptor
     */
    protected EntityDescriptor getEntityDescriptorById(String entityID, XMLObject metadata) {
        EntityDescriptor descriptor = null;

        log.debug("Searching for entity descriptor with an entity ID of {}", entityID);
        if (entityID != null && indexedDescriptors.containsKey(entityID)) {
            descriptor = indexedDescriptors.get(entityID);
            if (isValid(descriptor)) {
                log.trace("Entity descriptor for the ID {} was found in index cache, returning", entityID);
                return descriptor;
            } else {
                indexedDescriptors.remove(descriptor);
            }
        }

        if (metadata != null) {
            if (metadata instanceof EntityDescriptor) {
                log.trace("Metadata root is an entity descriptor, checking if it's the one we're looking for.");
                descriptor = (EntityDescriptor) metadata;
                if (!DataTypeHelper.safeEquals(descriptor.getEntityID(), entityID)) {
                    // skip this one, it isn't what we're looking for
                    descriptor = null;
                } else if (!isValid(descriptor)) {
                    log.trace("Found entity descriptor for entity with ID {} but it is no longer valid, skipping it.",
                              entityID);
                    descriptor = null;
                }
            } else {
                log.trace("Metadata was an EntitiesDescriptor, checking if any of its descendant EntityDescriptor "
                              + "elements is the one we're looking for.");
                if (metadata instanceof EntitiesDescriptor) {
                    descriptor = getEntityDescriptorById(entityID, (EntitiesDescriptor) metadata);
                }
            }
        }

        if (descriptor != null) {
            log.trace("Located entity descriptor, creating an index to it for faster lookups");
            indexedDescriptors.put(entityID, descriptor);
        }

        return descriptor;
    }

    /**
     * Gets the entity descriptor with the given ID that is a descendant of the given entities descriptor.
     *
     * @param entityID the ID of the entity whose descriptor is to be fetched
     * @param descriptor the entities descriptor
     *
     * @return the entity descriptor
     */
    protected EntityDescriptor getEntityDescriptorById(String entityID, EntitiesDescriptor descriptor) {
        log.trace("Checking to see if EntitiesDescriptor {} contains the requested descriptor", descriptor.getName());
        List<EntityDescriptor> entityDescriptors = descriptor.getEntityDescriptors();
        if (entityDescriptors != null && !entityDescriptors.isEmpty()) {
            for (EntityDescriptor entityDescriptor : entityDescriptors) {
                log.trace("Checking entity descriptor with entity ID {}", entityDescriptor.getEntityID());
                if (DataTypeHelper.safeEquals(entityDescriptor.getEntityID(), entityID) && isValid(entityDescriptor)) {
                    return entityDescriptor;
                }
            }
        }

        log.trace("Checking to see if any of the child entities descriptors contains the entity descriptor requested");
        EntityDescriptor entityDescriptor;
        List<EntitiesDescriptor> entitiesDescriptors = descriptor.getEntitiesDescriptors();
        if (entitiesDescriptors != null && !entitiesDescriptors.isEmpty()) {
            for (EntitiesDescriptor entitiesDescriptor : descriptor.getEntitiesDescriptors()) {
                entityDescriptor = getEntityDescriptorById(entityID, entitiesDescriptor);
                if (entityDescriptor != null) {
                    // We don't need to check for validity because getEntityDescriptorById only returns a valid
                    // descriptor
                    return entityDescriptor;
                }
            }
        }

        return null;
    }

    /**
     * Gets the entities descriptor with the given name.
     *
     * @param name name of the entities descriptor
     * @param rootDescriptor the root descriptor to search in
     *
     * @return the EntitiesDescriptor with the given name
     */
    protected EntitiesDescriptor getEntitiesDescriptorByName(String name, EntitiesDescriptor rootDescriptor) {
        EntitiesDescriptor descriptor = null;

        if (DataTypeHelper.safeEquals(name, rootDescriptor.getName()) && isValid(rootDescriptor)) {
            descriptor = rootDescriptor;
        } else {
            List<EntitiesDescriptor> childDescriptors = rootDescriptor.getEntitiesDescriptors();
            if (childDescriptors == null || childDescriptors.isEmpty()) {
                return null;
            }

            for (EntitiesDescriptor childDescriptor : childDescriptors) {
                childDescriptor = getEntitiesDescriptorByName(name, childDescriptor);
                if (childDescriptor != null) {
                    descriptor = childDescriptor;
                }
            }
        }

        return descriptor;
    }

    /**
     * Returns whether the given descriptor is valid. If valid metadata is not required this method always returns true.
     *
     * @param descriptor the descriptor to check
     *
     * @return true if valid metadata is not required or the given descriptor is valid, false otherwise
     */
    protected boolean isValid(XMLObject descriptor) {
        if (descriptor == null) {
            return false;
        }

        if (!requireValidMetadata()) {
            return true;
        }

        return SAML2Helper.isValid(descriptor);
    }
}