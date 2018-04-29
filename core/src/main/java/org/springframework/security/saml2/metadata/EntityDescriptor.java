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

package org.springframework.security.saml2.metadata;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.datatype.Duration;
import java.util.LinkedList;
import java.util.List;

import org.joda.time.DateTime;
import org.springframework.security.saml2.Saml2Object;
import org.springframework.security.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml2.signature.DigestMethod;
import org.springframework.security.saml2.xml.SimpleKey;

import static org.springframework.security.saml2.init.SpringSecuritySaml.durationToMillis;
import static org.springframework.security.saml2.init.SpringSecuritySaml.millisToDuration;

/**
 * EntityDescriptor as defined in
 * <a href="https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf">
 *     Line 466-494
 * </a>
 */
public class EntityDescriptor<T extends EntityDescriptor> implements Saml2Object {

    private String id;
    private String entityId;
    private String entityAlias;
    private DateTime validUntil;
    private Duration cacheDuration;
    private List<? extends Provider> providers;
    private List<XMLSignature> signatures;
    private List<SimpleKey> keys;
    private SimpleKey signingKey;
    private AlgorithmMethod algorithm;
    private DigestMethod digest;

    @SuppressWarnings("unchecked")
    protected T _this() {
        return (T) this;
    }

    public String getId() {
        return id;
    }

    public String getEntityId() {
        return entityId;
    }

    /**
     *
     * @return the timestamp of the metadata expiration date. null if this value has not been set.
     */
    public DateTime getValidUntil() {
        return validUntil;
    }

    /**
     * The time interval in format "PnYnMnDTnHnMnS"
     * <ul>
     *   <li>P indicates the period (required)</li>
     *   <li>nY indicates the number of years</li>
     *   <li>nM indicates the number of months</li>
     *   <li>nD indicates the number of days</li>
     *   <li>T indicates the start of a time section (required if you are going to specify hours, minutes, or seconds)</li>
     *   <li>nH indicates the number of hours</li>
     *   <li>nM indicates the number of minutes</li>
     *   <li>nS indicates the number of seconds</li>
     * </ul>
     * @return the cache duration for the metadata. null if no duration has been set.
     */
    public Duration getCacheDuration() {
        return cacheDuration;
    }

    /**
     * Transforms {@link #getCacheDuration()} into milli seconds.
     * @return returns the number of milli seconds this metadata should be cached for. -1 if the value is not set.
     */
    public long getCacheDurationMillis() {
        return durationToMillis(getCacheDuration());

    }

    public List<? extends Provider> getProviders() {
        return providers;
    }

    public List<SsoProvider> getSsoProviders() {
        List<SsoProvider> result = new LinkedList<>();
        if (getProviders()!=null) {
            getProviders()
                .stream()
                .filter(p -> p instanceof SsoProvider)
                .forEach(p -> result.add((SsoProvider) p));
        }
        return result;
    }

    public List<XMLSignature> getSignatures() {
        return signatures;
    }

    public List<SimpleKey> getKeys() {
        return keys;
    }

    public SimpleKey getSigningKey() {
        return signingKey;
    }

    public T setId(String id) {
        this.id = id;
        return _this();
    }

    public T setEntityId(String entityId) {
        this.entityId = entityId;
        return _this();
    }

    public T setValidUntil(DateTime validUntil) {
        this.validUntil = validUntil;
        return _this();
    }

    public T setCacheDuration(Duration cacheDuration) {
        this.cacheDuration = cacheDuration;
        return _this();
    }

    public T setCacheDurationMillis(long millis) {
        return setCacheDuration(millisToDuration(millis));
    }

    public T setProviders(List<? extends Provider> providers) {
        this.providers = providers;
        return _this();
    }

    public T setSignatures(List<XMLSignature> signatures) {
        this.signatures = signatures;
        return _this();
    }

    public T setKeys(List<SimpleKey> keys) {
        this.keys = keys;
        return _this();
    }

    public T setSigningKey(SimpleKey signingKey, AlgorithmMethod algorithm, DigestMethod digest) {
        this.signingKey = signingKey;
        this.algorithm = algorithm;
        this.digest = digest;
        return _this();
    }

    public AlgorithmMethod getAlgorithm() {
        return algorithm;
    }

    public DigestMethod getDigest() {
        return digest;
    }

    public String getEntityAlias() {
        return entityAlias;
    }

    public T setEntityAlias(String entityAlias) {
        this.entityAlias = entityAlias;
        return _this();
    }
}
