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
import org.opensaml.saml2.metadata.provider.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.*;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.PKIXSignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.trust.AllowAllSignatureTrustEngine;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.Assert;

import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Class offers extra services on top of the underlying chaining MetadataProviders. Manager keeps track of all available
 * identity and service providers configured inside the chained metadata providers. Exactly one service provider can
 * be determined as hosted.
 * <p>
 * The class is synchronized using in internal ReentrantReadWriteLock.
 * <p>
 * All metadata providers are kept in two groups - available providers - which contain all the ones users have registered,
 * and active providers - all those which passed validation. List of active providers is updated during each refresh.
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

    // Internal of metadata refresh checking in ms
    private long refreshCheckInterval = 10000l;

    // Flag indicating whether metadata needs to be reloaded
    private boolean refreshRequired = true;

    // Storage for cryptographic data used to verify metadata signatures
    protected KeyManager keyManager;

    // All providers which were added, not all may be active
    private List<ExtendedMetadataDelegate> availableProviders;

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
     * <p>
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
        availableProviders = new LinkedList<ExtendedMetadataDelegate>();

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

        Assert.notNull(keyManager, "KeyManager must be set");

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
     * Stops and removes the timer in case it was started. Cleans all metadata objects.
     */
    public void destroy() {

        try {

            refreshLock.writeLock().lock();
            lock.writeLock().lock();

            for (MetadataProvider provider : getProviders()) {
                if (provider instanceof ExtendedMetadataDelegate) {
                    ((ExtendedMetadataDelegate) provider).destroy();
                }
            }

            super.destroy();

            if (timer != null) {
                timer.cancel();
                timer.purge();
                timer = null;
            }

            // Workaround for Tomcat detection of terminated threads
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ie) {
            }

            setRefreshRequired(false);

        } finally {

            lock.writeLock().unlock();
            refreshLock.writeLock().unlock();

        }

    }

    @Override
    public void setProviders(List<MetadataProvider> newProviders) throws MetadataProviderException {

        try {

            lock.writeLock().lock();

            availableProviders.clear();
            if (newProviders != null) {
                for (MetadataProvider provider : newProviders) {
                    addMetadataProvider(provider);
                }
            }

        } finally {

            lock.writeLock().unlock();

        }

        setRefreshRequired(true);

    }

    /**
     * Method can be repeatedly called to browse all configured providers and load SP and IDP names which
     * are supported by them. Providers which fail during initialization are ignored for this refresh.
     */
    public void refreshMetadata() {

        log.debug("Reloading metadata");

        try {

            // Let's load new metadata lists
            lock.writeLock().lock();

            // Remove existing providers, they'll get repopulated
            super.setProviders(Collections.<MetadataProvider>emptyList());

            // Reinitialize the sets
            idpName = new HashSet<String>();
            spName = new HashSet<String>();
            aliasSet = new HashSet<String>();

            for (ExtendedMetadataDelegate provider : availableProviders) {

                try {

                    log.debug("Refreshing metadata provider {}", provider.toString());
                    initializeProviderFilters(provider);
                    initializeProvider(provider);
                    initializeProviderData(provider);

                    // Make provider available for queries
                    super.addMetadataProvider(provider);
                    log.debug("Metadata provider was initialized {}", provider.toString());

                } catch (MetadataProviderException e) {

                    log.error("Initialization of metadata provider " + provider + " failed, provider will be ignored", e);

                }

            }

            log.debug("Reloading metadata was finished");

        } catch (MetadataProviderException e) {

            throw new RuntimeException("Error clearing existing providers");

        } finally {

            lock.writeLock().unlock();

        }

    }

    /**
     * Determines whether metadata requires refresh and if so clears the flag.
     *
     * @return true in case refresh should be performed
     */
    private boolean isRefreshNowAndClear() {

        try {

            // Prevent anyone from changing the refresh status during reload to avoid missed calls
            refreshLock.writeLock().lock();

            // Make sure refresh is really necessary
            if (!isRefreshRequired()) {
                log.debug("Refresh is not required, isRefreshRequired flag isn't set");
                return false;
            }

            // Clear the refresh flag
            setRefreshRequired(false);

        } finally {

            refreshLock.writeLock().unlock();

        }

        return true;

    }

    /**
     * Adds a new metadata provider to the managed list. At first provider is only registered and will be validated
     * upon next round of metadata refreshing or call to refreshMetadata.
     * <p>
     * Unless provider already extends class ExtendedMetadataDelegate it will be automatically wrapped in it as part of the
     * addition.
     *
     * @param newProvider provider
     * @throws MetadataProviderException in case provider can't be added
     */
    @Override
    public void addMetadataProvider(MetadataProvider newProvider) throws MetadataProviderException {

        if (newProvider == null) {
            throw new IllegalArgumentException("Null provider can't be added");
        }

        try {

            lock.writeLock().lock();

            ExtendedMetadataDelegate wrappedProvider = getWrappedProvider(newProvider);
            availableProviders.add(wrappedProvider);

        } finally {
            lock.writeLock().unlock();
        }

        setRefreshRequired(true);

    }

    /**
     * Removes existing metadata provider from the availability list. Provider will be completely removed
     * during next manager refresh.
     *
     * @param provider provider to remove
     */
    @Override
    public void removeMetadataProvider(MetadataProvider provider) {

        if (provider == null) {
            throw new IllegalArgumentException("Null provider can't be removed");
        }

        try {

            lock.writeLock().lock();

            ExtendedMetadataDelegate wrappedProvider = getWrappedProvider(provider);
            availableProviders.remove(wrappedProvider);

        } finally {
            lock.writeLock().unlock();
        }

        setRefreshRequired(true);

    }

    /**
     * Method provides list of active providers - those which are valid and can be queried for metadata. Returned
     * value is a copy.
     *
     * @return active providers
     */
    public List<MetadataProvider> getProviders() {

        try {
            lock.readLock().lock();
            return new ArrayList<MetadataProvider>(super.getProviders());
        } finally {
            lock.readLock().unlock();
        }

    }

    /**
     * Method provides list of all available providers. Not all of these providers may be used in case their validation failed.
     * Returned value is a copy of the data.
     *
     * @return all available providers
     */
    public List<ExtendedMetadataDelegate> getAvailableProviders() {

        try {
            lock.readLock().lock();
            return new ArrayList<ExtendedMetadataDelegate>(availableProviders);
        } finally {
            lock.readLock().unlock();
        }

    }

    private ExtendedMetadataDelegate getWrappedProvider(MetadataProvider provider) {
        if (!(provider instanceof ExtendedMetadataDelegate)) {
            log.debug("Wrapping metadata provider {} with extendedMetadataDelegate", provider);
            return new ExtendedMetadataDelegate(provider);
        } else {
            return (ExtendedMetadataDelegate) provider;
        }
    }

    /**
     * Method is expected to make sure that the provider is properly initialized. Also all loaded filters should get
     * applied.
     *
     * @param provider provider to initialize
     * @throws MetadataProviderException error
     */
    protected void initializeProvider(ExtendedMetadataDelegate provider) throws MetadataProviderException {

        // Initialize provider and perform signature verification
        log.debug("Initializing extendedMetadataDelegate {}", provider);
        provider.initialize();

    }

    /**
     * Method populates local storage of IDP and SP names and verifies any name conflicts which might arise.
     *
     * @param provider provider to initialize
     * @throws MetadataProviderException error
     */
    protected void initializeProviderData(ExtendedMetadataDelegate provider) throws MetadataProviderException {

        log.debug("Initializing provider data {}", provider);

        List<String> stringSet = parseProvider(provider);

        for (String key : stringSet) {

            RoleDescriptor idpRoleDescriptor = provider.getRole(key, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);

            if (idpRoleDescriptor != null) {
                if (idpName.contains(key)) {
                    log.warn("Provider {} contains entity {} with IDP which was already contained in another metadata provider and will be ignored", provider, key);
                } else {
                    idpName.add(key);
                }
            }

            RoleDescriptor spRoleDescriptor = provider.getRole(key, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
            if (spRoleDescriptor != null) {
                if (spName.contains(key)) {
                    log.warn("Provider {} contains entity {} which was already included in another metadata provider and will be ignored", provider, key);
                } else {
                    spName.add(key);
                }
            }

            // Verify extended metadata
            ExtendedMetadata extendedMetadata = getExtendedMetadata(key, provider);

            if (extendedMetadata != null) {

                if (extendedMetadata.isLocal()) {

                    // Parse alias
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

                    // Set default local SP
                    if (spRoleDescriptor != null && getHostedSPName() == null) {
                        setHostedSPName(key);
                    }

                } else {

                    log.debug("Remote entity {} available", key);

                }

            } else {

                log.debug("No extended metadata available for entity {}", key);

            }

        }

    }

    /**
     * Method is automatically called during each attempt to initialize the provider data. It expects to load
     * all filters required for metadata verification. It must also be ensured that metadata provider is ready to be used
     * after call to this method.
     * <p>
     * Each provider must extend AbstractMetadataProvider or be of ExtendedMetadataDelegate type.
     * <p>
     * By default a SignatureValidationFilter is added together with any existing filters.
     *
     * @param provider provider to check
     * @throws MetadataProviderException in case initialization fails
     */
    protected void initializeProviderFilters(ExtendedMetadataDelegate provider) throws MetadataProviderException {

        if (provider.isTrustFiltersInitialized()) {

            log.debug("Metadata provider was already initialized, signature filter initialization will be skipped");

        } else {

            boolean requireSignature = provider.isMetadataRequireSignature();
            SignatureTrustEngine trustEngine = getTrustEngine(provider);
            SignatureValidationFilter filter = new SignatureValidationFilter(trustEngine);
            filter.setRequireSignature(requireSignature);

            log.debug("Created new trust manager for metadata provider {}", provider);

            // Combine any existing filters with the signature verification
            MetadataFilter currentFilter = provider.getMetadataFilter();
            if (currentFilter != null) {
                if (currentFilter instanceof MetadataFilterChain) {
                    log.debug("Adding signature filter into existing chain");
                    MetadataFilterChain chain = (MetadataFilterChain) currentFilter;
                    chain.getFilters().add(filter);
                } else {
                    log.debug("Combining signature filter with the existing in a new chain");
                    MetadataFilterChain chain = new MetadataFilterChain();
                    chain.getFilters().add(currentFilter);
                    chain.getFilters().add(filter);
                }
            } else {
                log.debug("Adding signature filter");
                provider.setMetadataFilter(filter);
            }

            provider.setTrustFiltersInitialized(true);

        }

    }

    /**
     * Method is expected to create a trust engine used to verify signatures from this provider.
     *
     * @param provider provider to create engine for
     * @return trust engine or null to skip trust verification
     */
    protected SignatureTrustEngine getTrustEngine(MetadataProvider provider) {

        Set<String> trustedKeys = null;
        boolean verifyTrust = true;
        boolean forceRevocationCheck = false;

        if (provider instanceof ExtendedMetadataDelegate) {
            ExtendedMetadataDelegate metadata = (ExtendedMetadataDelegate) provider;
            trustedKeys = metadata.getMetadataTrustedKeys();
            verifyTrust = metadata.isMetadataTrustCheck();
            forceRevocationCheck = metadata.isForceMetadataRevocationCheck();
        }

        if (verifyTrust) {

            log.debug("Setting trust verification for metadata provider {}", provider);

            CertPathPKIXValidationOptions pkixOptions = new CertPathPKIXValidationOptions();

            if (forceRevocationCheck) {
                log.debug("Revocation checking forced to true");
                pkixOptions.setForceRevocationEnabled(true);
            } else {
                log.debug("Revocation checking not forced");
                pkixOptions.setForceRevocationEnabled(false);
            }

            return new PKIXSignatureTrustEngine(
                    getPKIXResolver(provider, trustedKeys, null),
                    Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver(),
                    new org.springframework.security.saml.trust.CertPathPKIXTrustEvaluator(pkixOptions),
                    new BasicX509CredentialNameEvaluator());

        } else {

            log.debug("Trust verification skipped for metadata provider {}", provider);
            return new AllowAllSignatureTrustEngine(Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());

        }

    }

    /**
     * Method is expected to construct information resolver with all trusted data available for the given provider.
     *
     * @param provider     provider
     * @param trustedKeys  trusted keys for the providers
     * @param trustedNames trusted names for the providers (always null)
     * @return information resolver
     */
    protected PKIXValidationInformationResolver getPKIXResolver(MetadataProvider provider, Set<String> trustedKeys, Set<String> trustedNames) {

        // Use all available keys
        if (trustedKeys == null) {
            trustedKeys = keyManager.getAvailableCredentials();
        }

        // Resolve allowed certificates to build the anchors
        List<X509Certificate> certificates = new LinkedList<X509Certificate>();
        for (String key : trustedKeys) {
            log.debug("Adding PKIX trust anchor {} for metadata verification of provider {}", key, provider);
            X509Certificate certificate = keyManager.getCertificate(key);
            if (certificate != null) {
                certificates.add(certificate);
            } else {
                log.warn("Cannot construct PKIX trust anchor for key with alias {} for provider {}, key isn't included in the keystore", key, provider);
            }
        }

        List<PKIXValidationInformation> info = new LinkedList<PKIXValidationInformation>();
        info.add(new BasicPKIXValidationInformation(certificates, null, 4));
        return new StaticPKIXValidationInformationResolver(info, trustedNames);

    }

    /**
     * Parses the provider and returns set of entityIDs contained inside the provider.
     *
     * @param provider provider to parse
     * @return set of entityIDs available in the provider
     * @throws MetadataProviderException error
     */
    protected List<String> parseProvider(MetadataProvider provider) throws MetadataProviderException {

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
     * to the result set. Signatures on all found entities are verified using the given policy
     * and trust engine.
     *
     * @param result      result set of parsed entity IDs
     * @param descriptors descriptors to parse
     * @throws MetadataProviderException in case signature validation fails
     */
    private void addDescriptors(List<String> result, EntitiesDescriptor descriptors) throws MetadataProviderException {

        log.debug("Found metadata EntitiesDescriptor with ID", descriptors.getID());

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
     * Parses entityID from the descriptor and adds it to the result set.  Signatures on all found entities
     * are verified using the given policy and trust engine.
     *
     * @param result     result set
     * @param descriptor descriptor to parse
     * @throws MetadataProviderException in case signature validation fails
     */
    private void addDescriptor(List<String> result, EntityDescriptor descriptor) throws MetadataProviderException {

        String entityID = descriptor.getEntityID();
        log.debug("Found metadata EntityDescriptor with ID", entityID);
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
     * <p>
     * In case none of the providers can supply the extended version, the default is used.
     * <p>
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
                ExtendedMetadata extendedMetadata = getExtendedMetadata(entityID, provider);
                if (extendedMetadata != null) {
                    return extendedMetadata;
                }
            }

            return getDefaultExtendedMetadata().clone();

        } finally {

            lock.readLock().unlock();

        }

    }

    private ExtendedMetadata getExtendedMetadata(String entityID, MetadataProvider provider) throws MetadataProviderException {
        if (provider instanceof ExtendedMetadataProvider) {
            ExtendedMetadataProvider extendedProvider = (ExtendedMetadataProvider) provider;
            ExtendedMetadata extendedMetadata = extendedProvider.getExtendedMetadata(entityID);
            if (extendedMetadata != null) {
                return extendedMetadata.clone();
            }
        }
        return null;
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
                if (extendedMetadata.isLocal() && entityAlias.equals(extendedMetadata.getAlias())) {
                    if (entityId != null && !entityId.equals(idp)) {
                        throw new MetadataProviderException("Alias " + entityAlias + " is used both for entity " + entityId + " and " + idp);
                    } else {
                        entityId = idp;
                    }
                }
            }

            for (String sp : spName) {
                ExtendedMetadata extendedMetadata = getExtendedMetadata(sp);
                if (extendedMetadata.isLocal() && entityAlias.equals(extendedMetadata.getAlias())) {
                    if (entityId != null && !entityId.equals(sp)) {
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
     * <p>
     * In case the value is smaller than zero the timer is not created. The default value is 10000l.
     * <p>
     * The value can only be modified before the call to the afterBeanPropertiesSet, the changes are not applied after that.
     *
     * @param refreshCheckInterval internal, timer not created if &lt;= 2000
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

                log.trace("Executing metadata refresh task");

                // Invoking getMetadata performs a refresh in case it's needed
                // Potentially expensive operation, but other threads can still load existing cached data
                for (MetadataProvider provider : getProviders()) {
                    provider.getMetadata();
                }

                // Refresh the metadataManager if needed
                if (isRefreshRequired()) {
                    if (isRefreshNowAndClear()) {
                        refreshMetadata();
                    }
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

    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @Autowired(required = false)
    public void setTLSConfigurer(TLSProtocolConfigurer configurer) {
        // Only explicit dependency
    }

}