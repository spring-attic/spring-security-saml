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
import org.springframework.security.saml2.xml.KeyDescriptor;

public class Provider {

    private List<XMLSignature> signatures;
    private List<KeyDescriptor> keyDescriptors;
    private String id;
    private DateTime validUntil;
    private String cacheDuration;
    private String protocolSupportEnumeration;

    public List<XMLSignature> getSignatures() {
        return signatures;
    }

    public List<KeyDescriptor> getKeyDescriptors() {
        return keyDescriptors;
    }

    public String getId() {
        return id;
    }

    public DateTime getValidUntil() {
        return validUntil;
    }

    public String getCacheDuration() {
        return cacheDuration;

    }

    public String getProtocolSupportEnumeration() {
        return protocolSupportEnumeration;
    }



}
