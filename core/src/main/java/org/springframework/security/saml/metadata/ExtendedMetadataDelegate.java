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
import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;

/**
 * Class enables delegation of normal entity metadata loading to the selected provider while enhancing data with
 * extended metadata.
 */
public class ExtendedMetadataDelegate extends AbstractMetadataDelegate implements ExtendedMetadataProvider {

    // Class logger
    protected final Logger log = LoggerFactory.getLogger(ExtendedMetadataDelegate.class);

    /**
     * When true metadata will only be accepted if correctly signed.
     */
    private boolean metadataRequireSignature = false;

    /**
     * When true metadata signature will be verified for trust using PKIX with metadataTrustedKeys
     * as anchors.
     */
    private boolean metadataTrustCheck = true;

    /**
     * Determines whether check for certificate revocation should always be done as part of the PKIX validation.
     * Revocation is evaluated by the underlaying JCE implementation and depending on configuration may include
     * CRL and OCSP verification of the certificate in question.
     */
    private boolean forceMetadataRevocationCheck = false;

    /**
     * Keys stored in the KeyManager which can be used to verify whether signature of the metadata is trusted.
     * If not set any key stored in the keyManager is considered as trusted.
     */
    private Set<String> metadataTrustedKeys = null;

    /**
     * Metadata to use in case map doesn't contain any value.
     */
    private ExtendedMetadata defaultMetadata;

    /**
     * EntityID specific metadata.
     */
    private Map<String, ExtendedMetadata> extendedMetadataMap;

    /**
     * Flag indicates that delegated metadata already contains all information required to perform signature
     * and trust verification of the included metadata.
     */
    private boolean trustFiltersInitialized;

    /**
     * Uses provider for normal entity data, for each entity available in the delegate returns given defaults.
     *
     * @param delegate delegate with available entities
     */
    public ExtendedMetadataDelegate(MetadataProvider delegate) {
        this(delegate, null, null);
    }

    /**
     * Uses provider for normal entity data, for each entity available in the delegate returns given defaults.
     *
     * @param delegate        delegate with available entities
     * @param defaultMetadata default extended metadata, can be null
     */
    public ExtendedMetadataDelegate(MetadataProvider delegate, ExtendedMetadata defaultMetadata) {
        this(delegate, defaultMetadata, null);
    }

    /**
     * Uses provider for normal entity data, tries to locate extended metadata by search in the map.
     *
     * @param delegate            delegate with available entities
     * @param extendedMetadataMap map, can be null
     */
    public ExtendedMetadataDelegate(MetadataProvider delegate, Map<String, ExtendedMetadata> extendedMetadataMap) {
        this(delegate, null, extendedMetadataMap);
    }

    /**
     * Uses provider for normal entity data, tries to locate extended metadata by search in the map, in case it's not found
     * uses the default.
     *
     * @param delegate            delegate with available entities
     * @param defaultMetadata     default extended metadata, can be null
     * @param extendedMetadataMap map, can be null
     */
    public ExtendedMetadataDelegate(MetadataProvider delegate, ExtendedMetadata defaultMetadata, Map<String, ExtendedMetadata> extendedMetadataMap) {
        super(delegate);
        if (defaultMetadata == null) {
            this.defaultMetadata = new ExtendedMetadata();
        } else {
            this.defaultMetadata = defaultMetadata;
        }
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

    /**
     * Method performs initialization of the provider it delegates to.
     *
     * @throws MetadataProviderException in case initialization fails
     */
    public void initialize() throws MetadataProviderException {
        if (getDelegate() instanceof AbstractMetadataProvider) {
            log.debug("Initializing delegate");
            AbstractMetadataProvider provider = (AbstractMetadataProvider) getDelegate();
            provider.initialize();
        } else {
            log.debug("Cannot initialize delegate, doesn't extend AbstractMetadataProvider");
        }
    }

    /**
     * Method destroys the metadata delegate.
     */
    public void destroy() {
        if (getDelegate() instanceof AbstractMetadataProvider) {
            log.debug("Destroying delegate");
            AbstractMetadataProvider provider = (AbstractMetadataProvider) getDelegate();
            provider.destroy();
        } else {
            log.debug("Cannot destroy delegate, doesn't extend AbstractMetadataProvider");
        }
    }

    /**
     * If set returns set of keys which can be used to verify whether signature of the metadata is trusted. When
     * not set any of the keys in the configured KeyManager can be used to verify trust.
     * <p>
     * By default the value is null.
     *
     * @return trusted keys or null
     */
    public Set<String> getMetadataTrustedKeys() {
        return metadataTrustedKeys;
    }

    /**
     * Set of aliases of keys present in the KeyManager which can be used to verify whether signature on metadata entity
     * is trusted. When set to null any key of KeyManager can be used to verify trust.
     *
     * @param metadataTrustedKeys keys or null
     */
    public void setMetadataTrustedKeys(Set<String> metadataTrustedKeys) {
        this.metadataTrustedKeys = metadataTrustedKeys;
    }

    /**
     * Flag indicating whether metadata must be signed.
     * <p>
     * By default signature is not required.
     *
     * @return signature flag
     */
    public boolean isMetadataRequireSignature() {
        return metadataRequireSignature;
    }

    /**
     * When set to true metadata from this provider should only be accepted when correctly signed and verified. Metadata with
     * an invalid signature or signed by a not-trusted credential will be ignored.
     *
     * @param metadataRequireSignature flag to set
     */
    public void setMetadataRequireSignature(boolean metadataRequireSignature) {
        this.metadataRequireSignature = metadataRequireSignature;
    }

    public boolean isMetadataTrustCheck() {
        return metadataTrustCheck;
    }

    public void setMetadataTrustCheck(boolean metadataTrustCheck) {
        this.metadataTrustCheck = metadataTrustCheck;
    }

    public boolean isForceMetadataRevocationCheck() {
        return forceMetadataRevocationCheck;
    }

    /**
     * Determines whether check for certificate revocation should always be done as part of the PKIX validation.
     * Revocation is evaluated by the underlaying JCE implementation and depending on configuration may include
     * CRL and OCSP verification of the certificate in question.
     * <p>
     * When set to false revocation is only performed when MetadataManager includes CRLs
     *
     * @param forceMetadataRevocationCheck revocation flag
     */
    public void setForceMetadataRevocationCheck(boolean forceMetadataRevocationCheck) {
        this.forceMetadataRevocationCheck = forceMetadataRevocationCheck;
    }

    protected boolean isTrustFiltersInitialized() {
        return trustFiltersInitialized;
    }

    protected void setTrustFiltersInitialized(boolean trustFiltersInitialized) {
        this.trustFiltersInitialized = trustFiltersInitialized;
    }

    @Override
    public String toString() {
        return getDelegate().toString();
    }

}