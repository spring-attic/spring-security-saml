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
import org.opensaml.saml2.metadata.provider.ObservableMetadataProvider;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.Assert;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Class offers extra services on top of the underlying chaining MetadataProviders. Manager keeps track of all available
 * identity and service providers configured inside the chained metadata providers. Exactly one service provider can
 * be determined as hosted.
 * <p/>
 * The class is synchronized using in internal ReentrantReadWriteLock.
 *
 * @author Vladimir Schaefer
 */
public class MetadataManager extends ChainingMetadataProvider implements ExtendedMetadataProvider, InitializingBean, DisposableBean {

    // Class logger
    protected final Logger log = LoggerFactory.getLogger(MetadataManager.class);

    // Lock for the instance
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    // Lock for the refresh mechanism
    private final ReentrantReadWriteLock refreshLock = new ReentrantReadWriteLock();

    private String hostedSPName;
    private String defaultIDP;
    private ExtendedMetadata defaultExtendedMetadata;

    // Timer used to refresh the metadata upon changes
    private Timer timer;

    // Internal of metadata refresh checking
    private long refreshCheckInterval = 10000l;

    // Flag indicating whether metadata needs to be reloaded
    private boolean refreshRequired = true;

    /**
     * Set of IDP names available in the system.
     */
    private Set<String> idpName;

    /**
     * Set of SP names available in the system.
     */
    private Set<String> spName;

    /**
     * All valid aliases.
     */
    private Set<String> aliasSet;

    /**
     * Creates new metadata manager, automatically registers itself for notifications from metadata changes and calls
     * reload upon a change. Also registers timer which verifies whether metadata needs to be reloaded in a specified
     * time interval.
     * <p/>
     * It is mandatory that method afterPropertiesSet is called after the construction.
     *
     * @param providers providers to include, mustn't be null or empty
     * @throws MetadataProviderException error during initialization
     */
    public MetadataManager(List<MetadataProvider> providers) throws MetadataProviderException {

        super();

        this.idpName = new HashSet<String>();
        this.spName = new HashSet<String>();
        this.defaultExtendedMetadata = new ExtendedMetadata();

        setProviders(providers);
        getObservers().add(new MetadataProviderObserver());

    }

    /**
     * Method must be called after provider construction. It creates the refresh timer and refreshes the metadata for
     * the first time.
     *
     * @throws MetadataProviderException error
     */
    public final void afterPropertiesSet() throws MetadataProviderException {

        // Create timer if needed
        if (refreshCheckInterval > 0) {
            log.debug("Creating metadata reload timer with interval {}", refreshCheckInterval);
            this.timer = new Timer("Metadata-reload", true);
            this.timer.schedule(new RefreshTask(), refreshCheckInterval, refreshCheckInterval);
        } else {
            log.debug("Metadata reload timer is not created, refreshCheckInternal is {}", refreshCheckInterval);
        }

        refreshMetadata();

    }

    /**
     * Stops and removes the timer in case it was started.
     */
    public void destroy() {
        if (timer != null) {
            timer.cancel();
        }
    }

    /**
     * Method can be repeatedly called to browse all configured providers and load SP and IDP names which
     * are supported by them. Providers which fail during initialization are ignored for this refresh.
     */
    public void refreshMetadata() {

        try {

            // Prevent anyone from changing the refresh status during reload to avoid missed calls
            refreshLock.writeLock().lock();

            // Make sure refresh is really necessary
            if (!isRefreshRequired()) {
                log.debug("Refresh is not required, isRefreshRequired flag isn't set");
                return;
            }

            log.debug("Reloading metadata");

            try {

                // Let's load new metadata lists
                lock.writeLock().lock();

                // Reinitialize the sets
                idpName = new HashSet<String>();
                spName = new HashSet<String>();
                aliasSet = new HashSet<String>();

                for (MetadataProvider provider : getProviders()) {

                    try {

                        log.debug("Refreshing metadata provider {}", provider.toString());
                        initializeProvider(provider);

                    } catch (MetadataProviderException e) {

                        log.error("Initialization of metadata provider {} failed, provider will be ignored", provider, e);

                    }

                }

                // Clear the refresh flag
                setRefreshRequired(false);

                log.debug("Reloading metadata was finished");

            } finally {

                lock.writeLock().unlock();

            }

        } finally {

            refreshLock.writeLock().unlock();

        }

    }

    /**
     * Adds a new metadata provider to the managed list.
     *
     * @param newProvider provider
     * @throws MetadataProviderException in case provider can't be added
     */
    @Override
    public void addMetadataProvider(MetadataProvider newProvider) throws MetadataProviderException {

        try {

            lock.writeLock().lock();
            super.addMetadataProvider(newProvider);
            setRefreshRequired(true);

        } finally {
            lock.writeLock().unlock();
        }

    }

    @Override
    public void removeMetadataProvider(MetadataProvider provider) {

        try {

            lock.writeLock().lock();
            super.removeMetadataProvider(provider);
            setRefreshRequired(true);

        } finally {
            lock.writeLock().unlock();
        }

    }

    private void initializeProvider(MetadataProvider provider) throws MetadataProviderException {

        List<String> stringSet = parseProvider(provider);

        for (String key : stringSet) {

            RoleDescriptor roleDescriptor;
            roleDescriptor = provider.getRole(key, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);

            if (roleDescriptor != null) {
                if (idpName.contains(key)) {
                    log.warn("Provider {} contains entity {} with IDP which was already contained in another metadata provider and will be ignored", provider, key);
                } else {
                    idpName.add(key);
                }
            }

            roleDescriptor = provider.getRole(key, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
            if (roleDescriptor != null) {
                if (spName.contains(key)) {
                    log.warn("Provider {} contains entity {} which SP which was already contained in another metadata provider and will be ignored", provider, key);
                } else {
                    spName.add(key);
                }
            }

            // Verify extended metadata
            ExtendedMetadata extendedMetadata = getExtendedMetadata(key);

            if (extendedMetadata.isLocal()) {

                String alias = extendedMetadata.getAlias();
                if (alias != null) {

                    // Verify alias is valid
                    SAMLUtil.verifyAlias(alias, key);

                    // Verify alias is unique
                    if (aliasSet.contains(alias)) {

                        log.warn("Provider {} contains alias {} which is not unique and will be ignored", provider, alias);

                    } else {

                        aliasSet.add(alias);
                        log.debug("Local entity {} available under alias {}", key, alias);

                    }

                } else {

                    log.debug("Local entity {} doesn't have an alias", key);

                }

            } else {

                log.debug("Remote entity {} available", key);

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
    private List<String> parseProvider(MetadataProvider provider) throws MetadataProviderException {

        List<String> result = new LinkedList<String>();

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
    private void addDescriptors(List<String> result, EntitiesDescriptor descriptors) {
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
    private void addDescriptor(List<String> result, EntityDescriptor descriptor) {

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
        try {
            lock.readLock().lock();
            // The set is never modified so we don't need to clone here, only make sure we get the right instance.
            return Collections.unmodifiableSet(idpName);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Returns set of names of all SPs entity names
     *
     * @return set of SP entity names available in the metadata
     */
    public Set<String> getSPEntityNames() {
        try {
            lock.readLock().lock();
            // The set is never modified so we don't need to clone here, only make sure we get the right instance.
            return Collections.unmodifiableSet(spName);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * @param idpID name of IDP to check
     * @return true if IDP entity ID is in the circle of trust with our entity
     */
    public boolean isIDPValid(String idpID) {
        try {
            lock.readLock().lock();
            return idpName.contains(idpID);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * @param spID entity ID of SP to check
     * @return true if given SP entity ID is valid in circle of trust
     */
    public boolean isSPValid(String spID) {
        try {
            lock.readLock().lock();
            return spName.contains(spID);
        } finally {
            lock.readLock().unlock();
        }
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

        try {

            lock.readLock().lock();

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

        } finally {

            lock.readLock().unlock();

        }

    }

    /**
     * Sets name of IDP to be used as default.
     *
     * @param defaultIDP IDP to set as default
     */
    public void setDefaultIDP(String defaultIDP) {
        this.defaultIDP = defaultIDP;
    }

    /**
     * Tries to locate ExtendedMetadata by trying one provider after another. Only providers implementing
     * ExtendedMetadataProvider are considered.
     * <p/>
     * In case none of the providers can supply the extended version, the default is used.
     * <p/>
     * A copy of the internal representation is always returned, modifying the returned object will not be reflected
     * in the subsequent calls.
     *
     * @param entityID entity ID to load extended metadata for
     * @return extended metadata or defaults
     * @throws MetadataProviderException never thrown
     */
    public ExtendedMetadata getExtendedMetadata(String entityID) throws MetadataProviderException {

        try {

            lock.readLock().lock();

            for (MetadataProvider provider : getProviders()) {
                if (provider instanceof ExtendedMetadataProvider) {
                    ExtendedMetadataProvider extendedProvider = (ExtendedMetadataProvider) provider;
                    ExtendedMetadata extendedMetadata = extendedProvider.getExtendedMetadata(entityID);
                    if (extendedMetadata != null) {
                        return extendedMetadata.clone();
                    }
                }
            }

            return getDefaultExtendedMetadata().clone();

        } finally {

            lock.readLock().unlock();

        }

    }

    /**
     * Locates entity descriptor whose entityId SHA-1 hash equals the one in the parameter.
     *
     * @param hash hash of the entity descriptor
     * @return found descriptor or null
     * @throws MetadataProviderException in case metadata required for processing can't be loaded
     */
    public EntityDescriptor getEntityDescriptor(byte[] hash) throws MetadataProviderException {

        try {

            lock.readLock().lock();

            for (String idp : idpName) {
                if (SAMLUtil.compare(hash, idp)) {
                    return getEntityDescriptor(idp);
                }
            }

            for (String sp : spName) {
                if (SAMLUtil.compare(hash, sp)) {
                    return getEntityDescriptor(sp);
                }
            }

            return null;

        } finally {

            lock.readLock().unlock();

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

        try {

            lock.readLock().lock();

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

        } finally {

            lock.readLock().unlock();

        }

    }

    /**
     * @return default extended metadata to be used in case no entity specific version exists, never null
     */
    public ExtendedMetadata getDefaultExtendedMetadata() {
        try {
            lock.readLock().lock();
            return defaultExtendedMetadata;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Sets default extended metadata to be used in case no version specific is available.
     *
     * @param defaultExtendedMetadata metadata, RuntimeException when null
     */
    public void setDefaultExtendedMetadata(ExtendedMetadata defaultExtendedMetadata) {
        Assert.notNull(defaultExtendedMetadata, "ExtendedMetadata parameter mustn't be null");
        lock.writeLock().lock();
        this.defaultExtendedMetadata = defaultExtendedMetadata;
        lock.writeLock().unlock();
    }

    /**
     * Flag indicating whether configuration of the metadata should be reloaded.
     *
     * @return true if reload is required
     */
    public boolean isRefreshRequired() {
        try {
            refreshLock.readLock().lock();
            return refreshRequired;
        } finally {
            refreshLock.readLock().unlock();
        }
    }

    /**
     * Indicates that the metadata should be reloaded as the provider configuration has changed.
     * Uses a separate locking mechanism to allow setting metadata refresh flag without interrupting existing readers.
     *
     * @param refreshRequired true if refresh is required
     */
    public void setRefreshRequired(boolean refreshRequired) {
        try {
            refreshLock.writeLock().lock();
            this.refreshRequired = refreshRequired;
        } finally {
            refreshLock.writeLock().unlock();
        }
    }


    /**
     * Interval in milliseconds used for re-verification of metadata and their reload. Upon trigger each provider
     * is asked to return it's metadata, which might trigger their reloading. In case metadata is reloaded the manager
     * is notified and automatically refreshes all internal data by calling refreshMetadata.
     * <p/>
     * In case the value is smaller than zero the timer is not created. The default value is 10000l.
     * <p/>
     * The value can only be modified before the call to the afterBeanPropertiesSet, the changes are not applied after that.
     *
     * @param refreshCheckInterval internal, timer not created if <= 2000
     */
    public void setRefreshCheckInterval(long refreshCheckInterval) {
        this.refreshCheckInterval = refreshCheckInterval;
    }

    /**
     * Task used to refresh the metadata when required.
     */
    private class RefreshTask extends TimerTask {

        @Override
        public void run() {

            try {

                log.debug("Executing metadata refresh task");

                // Invoking getMetadata performs a refresh in case it's needed
                // Potentially expensive operation, but other threads can still load existing cached data
                for (MetadataProvider provider : getProviders()) {
                    provider.getMetadata();
                }

                // Refresh the metadataManager if needed
                if (isRefreshRequired()) {
                    refreshMetadata();
                }

            } catch (Throwable e) {
                log.warn("Metadata refreshing has failed", e);
            }

        }

    }

    /**
     * Observer which clears the cache upon any notification from any provider.
     */
    private class MetadataProviderObserver implements ObservableMetadataProvider.Observer {

        /**
         * {@inheritDoc}
         */
        public void onEvent(MetadataProvider provider) {
            setRefreshRequired(true);
        }

    }

}