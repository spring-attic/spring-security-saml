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

package org.springframework.security.saml2.authentication;

import javax.xml.crypto.dsig.XMLSignature;
import java.util.List;

import org.joda.time.DateTime;

public class Request<T extends Request<T>> {

    protected T _this() {
        return (T) this;
    }

    private List<String> issuers;
    private List<XMLSignature> signatures;
    private List<Object> extensions;

    private String id;
    private String version;
    private DateTime issueInstant;
    private String destination;
    private String consent;

    public List<String> getIssuers() {
        return issuers;
    }

    public List<XMLSignature> getSignatures() {
        return signatures;
    }

    public List<Object> getExtensions() {
        return extensions;
    }

    public String getId() {
        return id;
    }

    public String getVersion() {
        return version;
    }

    public DateTime getIssueInstant() {
        return issueInstant;
    }

    public String getDestination() {
        return destination;
    }

    public String getConsent() {
        return consent;
    }

    public T setIssuers(List<String> issuers) {
        this.issuers = issuers;
        return _this();
    }

    public T setSignatures(List<XMLSignature> signatures) {
        this.signatures = signatures;
        return _this();
    }

    public T setExtensions(List<Object> extensions) {
        this.extensions = extensions;
        return _this();
    }

    public T setId(String id) {
        this.id = id;
        return _this();
    }

    public T setVersion(String version) {
        this.version = version;
        return _this();
    }

    public T setIssueInstant(DateTime issueInstant) {
        this.issueInstant = issueInstant;
        return _this();
    }

    public T setDestination(String destination) {
        this.destination = destination;
        return _this();
    }

    public T setConsent(String consent) {
        this.consent = consent;
        return _this();
    }
}
