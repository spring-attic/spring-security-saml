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
import java.util.List;

import org.joda.time.DateTime;
import org.springframework.security.saml2.xml.SimpleKey;

import static org.springframework.security.saml2.init.SpringSecuritySaml.millisToDuration;

public class Provider<T extends Provider<T>> {

    private List<XMLSignature> signatures;
    private List<SimpleKey> keys;
    private String id;
    private DateTime validUntil;
    private Duration cacheDuration;
    private List<String> protocolSupportEnumeration;

    @SuppressWarnings("unchecked")
    protected T _this() {
        return (T) this;
    }

    public List<XMLSignature> getSignatures() {
        return signatures;
    }

    public List<SimpleKey> getKeys() {
        return keys;
    }



    public String getId() {
        return id;
    }

    public DateTime getValidUntil() {
        return validUntil;
    }

    public Duration getCacheDuration() {
        return cacheDuration;

    }

    public List<String> getProtocolSupportEnumeration() {
        return protocolSupportEnumeration;
    }

    public T setSignatures(List<XMLSignature> signatures) {
        this.signatures = signatures;
        return (T) this;
    }

    public T setKeys(List<SimpleKey> keys) {
        this.keys = keys;
        return (T) this;
    }

    public T setId(String id) {
        this.id = id;
        return (T) this;
    }

    public T setValidUntil(DateTime validUntil) {
        this.validUntil = validUntil;
        return (T) this;
    }

    public T setCacheDuration(Duration cacheDuration) {
        this.cacheDuration = cacheDuration;
        return (T) this;
    }

    public T setCacheDurationMillis(long millis) {
        return setCacheDuration(millisToDuration(millis));
    }

    public T setProtocolSupportEnumeration(List<String> protocolSupportEnumeration) {
        this.protocolSupportEnumeration = protocolSupportEnumeration;
        return (T) this;
    }
}
