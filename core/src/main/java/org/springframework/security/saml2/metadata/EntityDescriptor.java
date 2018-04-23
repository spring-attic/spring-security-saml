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
import java.util.List;

import org.joda.time.DateTime;
import org.springframework.security.saml2.Saml2Object;

import static org.springframework.security.saml2.util.TimeUtil.*;
import static org.springframework.util.StringUtils.hasText;

/**
 * EntityDescriptor as defined in
 * <a href="https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf">
 *     Line 466-494
 * </a>
 */
public class EntityDescriptor implements Saml2Object {

    private String id;
    private String entityId;
    private DateTime validUntil;
    private String cacheDuration;
    private List<Provider> providers;
    private List<XMLSignature> signatures;

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
    public String getCacheDuration() {
        return cacheDuration;
    }

    /**
     * Transforms {@link #getCacheDuration()} into milli seconds.
     * @return returns the number of milli seconds this metadata should be cached for. -1 if the value is not set.
     */
    public long getCacheDurationMillis() {
        String duration = getCacheDuration();
        return hasText(duration) ? durationToMillis(duration) : -1;

    }

    public List<Provider> getProviderDescriptors() {
        return providers;
    }

    public List<XMLSignature> getSignatures() {
        return signatures;
    }

    public EntityDescriptor setId(String id) {
        this.id = id;
        return this;
    }

    public EntityDescriptor setEntityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    public EntityDescriptor setValidUntil(DateTime validUntil) {
        this.validUntil = validUntil;
        return this;
    }

    public EntityDescriptor setCacheDuration(String cacheDuration) {
        this.cacheDuration = cacheDuration;
        return this;
    }

    public EntityDescriptor setCacheDurationMillis(long millis) {
        return setCacheDuration(millisToDuration(millis));
    }

    public EntityDescriptor setProviders(List<Provider> providers) {
        this.providers = providers;
        return this;
    }

    public EntityDescriptor setSignatures(List<XMLSignature> signatures) {
        this.signatures = signatures;
        return this;
    }
}
