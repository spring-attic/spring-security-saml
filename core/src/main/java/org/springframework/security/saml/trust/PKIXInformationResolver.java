/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
 * Copyright [2011] [Vladimir Schafer]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.trust;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ObservableMetadataProvider;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.x509.BasicPKIXValidationInformation;
import org.opensaml.xml.security.x509.PKIXValidationInformation;
import org.opensaml.xml.security.x509.PKIXValidationInformationResolver;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.security.MetadataCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;

import javax.xml.namespace.QName;
import java.lang.ref.SoftReference;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Implementation resolves PKIX information based on extended metadata configuration and provider data.
 * Values are cached and automatically cleared upon metadata refresh. At first data is loaded from the metadata
 * (or extended) metadata of the peer entity. In addition all trusted keys declared for the entity are also included.
 */
public class PKIXInformationResolver implements PKIXValidationInformationResolver {

    /**
     * Class logger.
     */
    private final Logger log = LoggerFactory.getLogger(MetadataCredentialResolver.class);

    /**
     * Metadata provider from which to fetch the credentials.
     */
    private MetadataManager metadata;

    /**
     * Cache of resolved credentials. [MetadataCacheKey, Credentials]
     */
    private Map<MetadataCacheKey, SoftReference<Collection<PKIXValidationInformation>>> cache;

    /**
     * Lock used to synchronize access to the credential cache.
     */
    private ReadWriteLock rwlock;

    /**
     * Resolver for metadata.
     */
    private MetadataCredentialResolver metadataResolver;

    /**
     * Key manager.
     */
    private KeyManager keyManager;

    /**
     * Constructor.
     *
     * @param metadataResolver resolver used to extract basic credentials out of metadata
     * @param metadataProvider provider of the metadata used to load extended metadata for an entity
     * @param keyManager       key manager
     * @throws IllegalArgumentException thrown if the supplied provider is null
     */
    public PKIXInformationResolver(MetadataCredentialResolver metadataResolver, MetadataManager metadataProvider, KeyManager keyManager) {

        if (metadataProvider == null) {
            throw new IllegalArgumentException("Metadata provider may not be null");
        }

        this.metadataResolver = metadataResolver;
        this.metadata = metadataProvider;
        this.keyManager = keyManager;
        this.cache = new HashMap<MetadataCacheKey, SoftReference<Collection<PKIXValidationInformation>>>();
        this.rwlock = new ReentrantReadWriteLock();
        this.metadata.getObservers().add(new MetadataProviderObserver());

    }

    /**
     * Get the lock instance used to synchronize access to the credential cache.
     *
     * @return a read-write lock instance
     */
    protected ReadWriteLock getReadWriteLock() {
        return rwlock;
    }

    protected Iterable<PKIXValidationInformation> resolveFromSource(CriteriaSet criteriaSet) throws SecurityException {

        checkCriteriaRequirements(criteriaSet);

        String entityID = criteriaSet.get(EntityIDCriteria.class).getEntityID();
        MetadataCriteria mdCriteria = criteriaSet.get(MetadataCriteria.class);
        QName role = mdCriteria.getRole();
        String protocol = mdCriteria.getProtocol();
        UsageCriteria usageCriteria = criteriaSet.get(UsageCriteria.class);
        UsageType usage;
        if (usageCriteria != null) {
            usage = usageCriteria.getUsage();
        } else {
            usage = UsageType.UNSPECIFIED;
        }

        // See Jira issue SIDP-229.
        log.debug("Forcing on-demand metadata provider refresh if necessary");
        try {
            metadata.getMetadata();
        } catch (MetadataProviderException e) {
            // don't care about errors at this level
        }

        MetadataCacheKey cacheKey = new MetadataCacheKey(entityID, role, protocol, usage);
        Collection<PKIXValidationInformation> credentials = retrieveFromCache(cacheKey);

        if (credentials == null) {
            credentials = populateCredentials(criteriaSet);
            cacheCredentials(cacheKey, credentials);
        }

        return credentials;
    }

    /**
     * Method responsible for loading of PKIX information.
     *
     * @param criteriaSet criteria for selection of data to include
     * @throws SecurityException in case credentials cannot be populated
     * @return PKIX information
     */
    protected Collection<PKIXValidationInformation> populateCredentials(CriteriaSet criteriaSet) throws SecurityException {
        Collection<X509Certificate> anchors = new ArrayList<X509Certificate>();
        Collection<X509CRL> crls = new ArrayList<X509CRL>();
        populateMetadataAnchors(criteriaSet, anchors, crls);
        populateTrustedKeysAnchors(criteriaSet, anchors, crls);
        populateCRLs(criteriaSet, anchors, crls);
        PKIXValidationInformation info = new BasicPKIXValidationInformation(anchors, crls, getPKIXDepth());
        return new ArrayList<PKIXValidationInformation>(Arrays.asList(info));
    }

    /**
     * Check that all necessary credential criteria are available.
     *
     * @param criteriaSet the credential set to evaluate
     */
    protected void checkCriteriaRequirements(CriteriaSet criteriaSet) {
        EntityIDCriteria entityCriteria = criteriaSet.get(EntityIDCriteria.class);
        MetadataCriteria mdCriteria = criteriaSet.get(MetadataCriteria.class);
        if (entityCriteria == null) {
            throw new IllegalArgumentException("Entity criteria must be supplied");
        }
        if (mdCriteria == null) {
            throw new IllegalArgumentException("SAML metadata criteria must be supplied");
        }
        if (DatatypeHelper.isEmpty(entityCriteria.getEntityID())) {
            throw new IllegalArgumentException("Credential owner entity ID criteria value must be supplied");
        }
        if (mdCriteria.getRole() == null) {
            throw new IllegalArgumentException("Credential metadata role criteria value must be supplied");
        }
    }

    /**
     * Retrieves pre-resolved credentials from the cache.
     *
     * @param cacheKey the key to the metadata cache
     * @return the collection of cached credentials or null
     */
    protected Collection<PKIXValidationInformation> retrieveFromCache(MetadataCacheKey cacheKey) {
        log.debug("Attempting to retrieve credentials from cache using index: {}", cacheKey);
        Lock readLock = getReadWriteLock().readLock();
        readLock.lock();
        log.trace("Read lock over cache acquired");
        try {
            if (cache.containsKey(cacheKey)) {
                SoftReference<Collection<PKIXValidationInformation>> reference = cache.get(cacheKey);
                if (reference.get() != null) {
                    log.debug("Retrieved credentials from cache using index: {}", cacheKey);
                    return reference.get();
                }
            }
        } finally {
            readLock.unlock();
            log.trace("Read lock over cache released");
        }

        log.debug("Unable to retrieve credentials from cache using index: {}", cacheKey);
        return null;
    }

    /**
     * Method loads credentials satisfying the criteriaSet from the metadata of the related entity.
     *
     * @param criteriaSet     criteria set
     * @param anchors pkix anchors
     * @param crls CRLs for the anchors
     * @throws SecurityException thrown if the key, certificate, or CRL information is represented in an unsupported format
     */
    protected void populateMetadataAnchors(CriteriaSet criteriaSet, Collection<X509Certificate> anchors, Collection<X509CRL> crls) throws SecurityException {

        String entityID = criteriaSet.get(EntityIDCriteria.class).getEntityID();
        log.debug("Attempting to retrieve PKIX trust anchors from metadata configuration for entity: {}", entityID);
        Iterable<Credential> metadataCredentials = metadataResolver.resolve(criteriaSet);

        for (Credential key : metadataCredentials) {
            if (key instanceof X509Credential) {
                X509Credential cred = (X509Credential) key;
                log.debug("Using key {} as a trust anchor", cred.getEntityCertificate().getSubjectDN());
                anchors.add(cred.getEntityCertificate());
            } else {
                log.debug("Key {} is not of X509Credential type, skipping", key.getEntityId());
            }
        }

    }

    /**
     * Method add trusted anchors which include all trusted certificates configuration
     * in the ExtendedMetadata. In case no trusted certificates were configured all certificates in the KeyManager
     * are considered as trusted and added to the anchor list.
     *
     * @param criteriaSet     criteria set
     * @param anchors pkix anchors
     * @param crls CRLs for the anchors
     * @throws SecurityException thrown if the key, certificate, or CRL information is represented in an unsupported
     *                           format
     */
    protected void populateTrustedKeysAnchors(CriteriaSet criteriaSet, Collection<X509Certificate> anchors, Collection<X509CRL> crls)
            throws SecurityException {

        try {

            String entityID = criteriaSet.get(EntityIDCriteria.class).getEntityID();
            log.debug("Attempting to retrieve credentials from metadata configuration for entity: {}", entityID);
            Set<String> trustedKeys;

            ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(entityID);

            if (extendedMetadata.getTrustedKeys() != null) {
                trustedKeys = extendedMetadata.getTrustedKeys();
            } else {
                trustedKeys = keyManager.getAvailableCredentials();
            }

            for (String key : trustedKeys) {
                anchors.add(keyManager.getCertificate(key));
            }

        } catch (MetadataProviderException e) {
            throw new SecurityException("Error loading extended metadata", e);
        }

    }

    /**
     * Extension points for loading of certificate revocation lists.
     *
     * @param criteriaSet     criteria set
     * @param anchors pkix anchors
     * @param crls crls to be populated
     * @throws SecurityException never thrown in default implementation
     */
    protected void populateCRLs(CriteriaSet criteriaSet, Collection<X509Certificate> anchors, Collection<X509CRL> crls)
            throws SecurityException {
    }

    /**
     * Allowed depth of PKIX trust path length.
     *
     * @return by default 5
     */
    protected int getPKIXDepth() {
        return 5;
    }

    /**
     * Adds resolved credentials to the cache.
     *
     * @param cacheKey    the key for caching the credentials
     * @param credentials collection of credentials to cache
     */
    protected void cacheCredentials(MetadataCacheKey cacheKey, Collection<PKIXValidationInformation> credentials) {
        Lock writeLock = getReadWriteLock().writeLock();
        writeLock.lock();
        log.trace("Write lock over cache acquired");
        try {
            cache.put(cacheKey, new SoftReference<Collection<PKIXValidationInformation>>(credentials));
            log.debug("Added new credential collection to cache with key: {}", cacheKey);
        } finally {
            writeLock.unlock();
            log.trace("Write lock over cache released");
        }
    }

    /**
     * A class which serves as the key into the cache of credentials previously resolved.
     */
    protected class MetadataCacheKey {

        /**
         * Entity ID of credential owner.
         */
        private String id;

        /**
         * Role in which the entity is operating.
         */
        private QName role;

        /**
         * Protocol over which the entity is operating (may be null).
         */
        private String protocol;

        /**
         * Intended usage of the resolved credentials.
         */
        private UsageType usage;

        /**
         * Constructor.
         *
         * @param entityID       entity ID of the credential owner
         * @param entityRole     role in which the entity is operating
         * @param entityProtocol protocol over which the entity is operating (may be null)
         * @param entityUsage    usage of the resolved credentials
         */
        protected MetadataCacheKey(String entityID, QName entityRole, String entityProtocol, UsageType entityUsage) {
            if (entityID == null) {
                throw new IllegalArgumentException("Entity ID may not be null");
            }
            if (entityRole == null) {
                throw new IllegalArgumentException("Entity role may not be null");
            }
            if (entityUsage == null) {
                throw new IllegalArgumentException("Credential usage may not be null");
            }
            id = entityID;
            role = entityRole;
            protocol = entityProtocol;
            usage = entityUsage;
        }

        /**
         * {@inheritDoc}
         */
        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof MetadataCacheKey)) {
                return false;
            }
            MetadataCacheKey other = (MetadataCacheKey) obj;
            if (!this.id.equals(other.id) || !this.role.equals(other.role) || this.usage != other.usage) {
                return false;
            }
            if (this.protocol == null) {
                if (other.protocol != null) {
                    return false;
                }
            } else {
                if (!this.protocol.equals(other.protocol)) {
                    return false;
                }
            }
            return true;
        }

        /**
         * {@inheritDoc}
         */
        public int hashCode() {
            int result = 17;
            result = 37 * result + id.hashCode();
            result = 37 * result + role.hashCode();
            if (protocol != null) {
                result = 37 * result + protocol.hashCode();
            }
            result = 37 * result + usage.hashCode();
            return result;
        }

        /**
         * {@inheritDoc}
         */
        public String toString() {
            return String.format("[%s,%s,%s,%s]", id, role, protocol, usage);
        }

    }

    /**
     * An observer that clears the credential cache if the underlying metadata changes.
     */
    protected class MetadataProviderObserver implements ObservableMetadataProvider.Observer {

        /**
         * {@inheritDoc}
         */
        public void onEvent(MetadataProvider provider) {
            Lock writeLock = getReadWriteLock().writeLock();
            writeLock.lock();
            log.trace("Write lock over cache acquired");
            try {
                cache.clear();
                log.debug("Credential cache cleared");
            } finally {
                writeLock.unlock();
                log.trace("Write lock over cache released");
            }
        }
    }

    public Set<String> resolveTrustedNames(CriteriaSet criteriaSet) throws org.opensaml.xml.security.SecurityException, UnsupportedOperationException {
        throw new UnsupportedOperationException("Method isn't supported");
    }

    public boolean supportsTrustedNameResolution() {
        return false;
    }

    public Iterable<PKIXValidationInformation> resolve(CriteriaSet criteria) throws SecurityException {
        return resolveFromSource(criteria);
    }

    /**
     * Returns first found PKIX information satisfying the condition.
     *
     * @param criteria criteria
     * @return first instance
     * @throws SecurityException error
     */
    public PKIXValidationInformation resolveSingle(CriteriaSet criteria) throws SecurityException {
        Iterator<PKIXValidationInformation> iterator = resolveFromSource(criteria).iterator();
        if (iterator.hasNext()) {
            return iterator.next();
        } else {
            return null;
        }
    }

}