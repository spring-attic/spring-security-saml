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

package org.springframework.security.saml.saml2.authentication;

import java.util.List;

import org.joda.time.DateTime;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.signature.Signature;

public class Request<T extends Request<T>> {

    protected T _this() {
        return (T) this;
    }

    private Issuer issuer;
    private Signature signature;
    private List<Object> extensions;

    private String id;
    private DateTime issueInstant;
    private Endpoint destination;
    private String consent;
    private String version;

    public Issuer getIssuer() {
        return issuer;
    }

    public Signature getSignature() {
        return signature;
    }

    public List<Object> getExtensions() {
        return extensions;
    }

    public String getId() {
        return id;
    }

    public DateTime getIssueInstant() {
        return issueInstant;
    }

    public Endpoint getDestination() {
        return destination;
    }

    public String getConsent() {
        return consent;
    }

    public T setIssuer(Issuer issuer) {
        this.issuer = issuer;
        return _this();
    }

    public T setSignature(Signature signature) {
        this.signature = signature;
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

    public T setIssueInstant(DateTime issueInstant) {
        this.issueInstant = issueInstant;
        return _this();
    }

    public T setDestination(Endpoint destination) {
        this.destination = destination;
        return _this();
    }

    public T setConsent(String consent) {
        this.consent = consent;
        return _this();
    }

    public String getVersion() {
        return version;
    }

    public T setVersion(String version) {
        this.version = version;
        return _this();
    }
}
