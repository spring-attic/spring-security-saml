/* Copyright 2009-2011 Vladimir Schäfer
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

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Class offers extra services on top of the underlying chaining MetadataProviders. Manager keeps track of all available
 * identity and service providers configured inside the chained metadata providers. Exactly one service provider can
 * be determined as hosted.
 *
 * @author Vladimir Schäfer
 */
public class MetadataManager extends ChainingMetadataProvider implements ExtendedMetadataProvider {

    private final Logger log = LoggerFactory.getLogger(MetadataManager.class);

    private String hostedSPName;
    private String defaultIDP;
    private ExtendedMetadata defaultExtendedMetadata;

    /**
     * Set of IDP names available in the system.
     */
    private Set<String> idpName;

    /**
     * Set of SP names available in the system.
     */
    private Set<String> spName;

    public MetadataManager(List<MetadataProvider> providers) throws MetadataProviderException {

        super();

        this.idpName = new HashSet<String>();
        this.spName = new HashSet<String>();
        this.defaultExtendedMetadata = new ExtendedMetadata();

        setProviders(providers);
        initialize();

    }

    /**
     * Method can be repeatedly called to browse all configured providers and load SP and IDP names which
     * are supported by them.
     *
     * @throws MetadataProviderException error parsing data
     */
    protected synchronized void initialize() throws MetadataProviderException {

        idpName.clear();
        spName.clear();

        for (MetadataProvider provider : getProviders()) {

            Set<String> stringSet = parseProvider(provider);
            for (String key : stringSet) {

                RoleDescriptor roleDescriptor;
                roleDescriptor = provider.getRole(key, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);

                if (roleDescriptor != null) {
                    if (idpName.contains(key)) {
                        throw new MetadataProviderException("Metadata contains two entities with the same entityID: " + key);
                    } else {
                        idpName.add(key);
                    }
                }

                roleDescriptor = provider.getRole(key, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
                if (roleDescriptor != null) {
                    if (spName.contains(key)) {
                        throw new MetadataProviderException("Metadata contains two entities with the same entityID: " + key);
                    } else {
                        spName.add(key);
                    }
                }

                // Verify alias is unique
                //getEntityIdForAlias(getExtendedMetadata(key).getAlias());

            }

        }

    }

    /**
     * Parses the provider and returns set of entityIDs contained inside the provider.
     *
     * @param provider provider to parse
     * @return set of entityIDs available in the provider
     * @throws MetadataProviderException error
     */
    private Set<String> parseProvider(MetadataProvider provider) throws MetadataProviderException {
        Set<String> result = new HashSet<String>();
        XMLObject object = provider.getMetadata();
        if (object instanceof EntityDescriptor) {
            addDescriptor(result, (EntityDescriptor) object);
        } else if (object instanceof EntitiesDescriptor) {
            addDescriptors(result, (EntitiesDescriptor) object);
        }
        return result;
    }

    /**
     * Recursively parses descriptors object. Supports both nested entitiesDescriptor
     * elements and leaf entityDescriptors. EntityID of all found descriptors are added
     * to the result set.
     *
     * @param result      result set
     * @param descriptors descriptors to parse
     */
    private void addDescriptors(Set<String> result, EntitiesDescriptor descriptors) {
        if (descriptors.getEntitiesDescriptors() != null) {
            for (EntitiesDescriptor descriptor : descriptors.getEntitiesDescriptors()) {
                addDescriptors(result, descriptor);
            }
        }
        if (descriptors.getEntityDescriptors() != null) {
            for (EntityDescriptor descriptor : descriptors.getEntityDescriptors()) {
                addDescriptor(result, descriptor);
            }
        }
    }

    /**
     * Parses entityID from the descriptor and adds it to the result set.
     *
     * @param result     result set
     * @param descriptor descriptor to parse
     */
    private void addDescriptor(Set<String> result, EntityDescriptor descriptor) {
        String entityID = descriptor.getEntityID();
        log.debug("Found metadata entity with ID", entityID);
        result.add(entityID);
    }

    /**
     * Returns set of names of all IDPs available in the metadata
     *
     * @return set of entityID names
     */
    public Set<String> getIDPEntityNames() {
        return Collections.unmodifiableSet(idpName);
    }

    /**
     * Returns set of names of all SPs entity names
     *
     * @return set of SP entity names available in the metadata
     */
    public Set<String> getSPEntityNames() {
        return Collections.unmodifiableSet(spName);
    }

    /**
     * @param idpID name of IDP to check
     * @return true if IDP entity ID is in the circle of trust with our entity
     */
    public boolean isIDPValid(String idpID) {
        return idpName.contains(idpID);
    }

    /**
     * @param spID entity ID of SP to check
     * @return true if given SP entity ID is valid in circle of trust
     */
    public boolean isSPValid(String spID) {
        return spName.contains(spID);
    }

    /**
     * The method returns name of SP running this application. This name is either set from spring
     * context of automatically by invoking of the metadata filter.
     *
     * @return name of hosted SP metadata which can be returned by call to getEntityDescriptor.
     */
    public String getHostedSPName() {
        return hostedSPName;
    }

    /**
     * Sets nameID of SP hosted on this machine. This can either be called from springContext or
     * automatically during invocation of metadata generation filter.
     *
     * @param hostedSPName name of metadata describing SP hosted on this machine
     */
    public void setHostedSPName(String hostedSPName) {
        this.hostedSPName = hostedSPName;
    }

    /**
     * Returns entity ID of the IDP to be used by default. In case the defaultIDP property has been set
     * it is returned. Otherwise first available IDP in IDP list is used.
     *
     * @return entity ID of IDP to use
     * @throws MetadataProviderException in case IDP can't be determined
     */
    public String getDefaultIDP() throws MetadataProviderException {
        if (defaultIDP != null) {
            return defaultIDP;
        } else {
            Iterator<String> iterator = getIDPEntityNames().iterator();
            if (iterator.hasNext()) {
                return iterator.next();
            } else {
                throw new MetadataProviderException("No IDP was configured, please update included metadata with at least one IDP");
            }
        }
    }

    /**
     * Sets name of IDP to be used as default. In case the IDP is not present (wasn't loaded from any
     * metadata provider) runtime exception is thrown.
     *
     * @param defaultIDP IDP to set as default
     */
    public void setDefaultIDP(String defaultIDP) {

        for (String s : getIDPEntityNames()) {
            if (s.equals(defaultIDP)) {
                this.defaultIDP = defaultIDP;
                return;
            }
        }
        throw new IllegalArgumentException("Attempt to set nonexistent IDP as a default: " + defaultIDP);
    }

    /**
     * Tries to locate ExtendedMetadata by trying one provider after another. Only providers implementing
     * ExtendedMetadataProvider are considered.
     * <p/>
     * In case none of the providers can supply the extended version, the default is used.
     *
     * @param entityID entity ID to load extended metadata for
     * @return extended metadata or defaults
     * @throws MetadataProviderException never thrown
     */
    public ExtendedMetadata getExtendedMetadata(String entityID) throws MetadataProviderException {

        for (MetadataProvider provider : getProviders()) {
            if (provider instanceof ExtendedMetadataProvider) {
                ExtendedMetadataProvider extendedProvider = (ExtendedMetadataProvider) provider;
                ExtendedMetadata extendedMetadata = extendedProvider.getExtendedMetadata(entityID);
                if (extendedMetadata != null) {
                    return extendedMetadata;
                }
            }
        }

        return getDefaultExtendedMetadata();

    }

    /**
     * Locates entity descriptor whose entityId SHA-1 hash equals the one in the parameter.
     *
     * @param hash hash of the entity descriptor
     * @return found descriptor or null
     */
    public EntityDescriptor getEntityDescriptor(byte[] hash) throws MetadataProviderException {

        for (String idp : idpName) {
            if (compare(hash, idp)) {
                return getEntityDescriptor(idp);
            }
        }

        for (String sp : spName) {
            if (compare(hash, sp)) {
                return getEntityDescriptor(sp);
            }
        }

        return null;

    }

    /**
     * Compares whether SHA-1 hash of the entityId equals the hashID.
     *
     * @param hashID   hash id to compare
     * @param entityId entity id to hash and verify
     * @return true if values match
     * @throws MetadataProviderException in case SHA-1 hash can't be initialized
     */
    private boolean compare(byte[] hashID, String entityId) throws MetadataProviderException {

        try {

            MessageDigest sha1Digester = MessageDigest.getInstance("SHA-1");
            byte[] hashedEntityId = sha1Digester.digest(entityId.getBytes());

            for (int i = 0; i < hashedEntityId.length; i++) {
                if (hashedEntityId[i] != hashID[i]) {
                    return false;
                }
            }

            return true;

        } catch (NoSuchAlgorithmException e) {
            throw new MetadataProviderException("SHA-1 message digest not available", e);
        }

    }

    /**
     * Tries to load entityId for entity with the given alias. Fails in case two entities with the same alias
     * are configured in the system.
     *
     * @param entityAlias alias to locate id for
     * @return entity id for the given alias or null if none exists
     * @throws MetadataProviderException in case two entity have the same non-null alias
     */
    public String getEntityIdForAlias(String entityAlias) throws MetadataProviderException {

        if (entityAlias == null) {
            return null;
        }

        String entityId = null;

        for (String idp : idpName) {
            ExtendedMetadata extendedMetadata = getExtendedMetadata(idp);
            if (entityAlias.equals(extendedMetadata.getAlias())) {
                if (entityId != null) {
                    throw new MetadataProviderException("Alias " + entityAlias + " is used both for entity " + entityId + " and " + idp);
                } else {
                    entityId = idp;
                }
            }
        }

        for (String sp : spName) {
            ExtendedMetadata extendedMetadata = getExtendedMetadata(sp);
            if (entityAlias.equals(extendedMetadata.getAlias())) {
                if (entityId != null) {
                    throw new MetadataProviderException("Alias " + entityAlias + " is used both for entity " + entityId + " and " + sp);
                } else {
                    entityId = sp;
                }
            }
        }

        return entityId;

    }

    /**
     * @return default extended metadata to be used in case no entity specific version exists, never null
     */
    public ExtendedMetadata getDefaultExtendedMetadata() {
        return defaultExtendedMetadata;
    }

    /**
     * Sets default extended metadata to be used in case no version specific is available.
     *
     * @param defaultExtendedMetadata metadata, RuntimeException when null
     */
    public void setDefaultExtendedMetadata(ExtendedMetadata defaultExtendedMetadata) {
        Assert.notNull(defaultExtendedMetadata, "ExtendedMetadata parameter mustn'be null");
        this.defaultExtendedMetadata = defaultExtendedMetadata;
    }

}