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

import org.springframework.security.saml2.Saml2Object;
import org.springframework.security.saml2.metadata.Binding;
import org.springframework.security.saml2.metadata.Endpoint;
import org.springframework.security.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml2.signature.DigestMethod;
import org.springframework.security.saml2.xml.SimpleKey;

public class AuthenticationRequest extends Request<AuthenticationRequest> implements Saml2Object {

    private String providerName;
    private Binding binding;
    private Boolean forceAuth;
    private Boolean isPassive;
    private Endpoint assertionConsumerService;
    private RequestedAuthenticationContext requestedAuthenticationContext;
    private AuthenticationContextReference authenticationContextReference;
    private SimpleKey signingKey;
    private AlgorithmMethod algorithm;
    private DigestMethod digest;

    private NameIDPolicy nameIDPolicy;

    public String getProviderName() {
        return providerName;
    }

    public Binding getBinding() {
        return binding;
    }

    public Boolean isForceAuth() {
        return forceAuth;
    }

    public Boolean isPassive() {
        return isPassive;
    }

    public Endpoint getAssertionConsumerService() {
        return assertionConsumerService;
    }

    public RequestedAuthenticationContext getRequestedAuthenticationContext() {
        return requestedAuthenticationContext;
    }

    public AuthenticationContextReference getAuthenticationContextReference() {
        return authenticationContextReference;
    }

    public AuthenticationRequest setProviderName(String providerName) {
        this.providerName = providerName;
        return _this();
    }

    public AuthenticationRequest setBinding(Binding binding) {
        this.binding = binding;
        return _this();
    }

    public AuthenticationRequest setForceAuth(Boolean forceAuth) {
        this.forceAuth = forceAuth;
        return _this();
    }

    public AuthenticationRequest setPassive(Boolean passive) {
        isPassive = passive;
        return _this();
    }

    public AuthenticationRequest setAssertionConsumerService(Endpoint assertionConsumerService) {
        this.assertionConsumerService = assertionConsumerService;
        return _this();
    }

    public AuthenticationRequest setRequestedAuthenticationContext(RequestedAuthenticationContext requestedAuthenticationContext) {
        this.requestedAuthenticationContext = requestedAuthenticationContext;
        return _this();
    }

    public AuthenticationRequest setAuthenticationContextReference(AuthenticationContextReference authenticationContextReference) {
        this.authenticationContextReference = authenticationContextReference;
        return _this();
    }

    public SimpleKey getSigningKey() {
        return signingKey;
    }

    public AuthenticationRequest setSigningKey(SimpleKey signingKey, AlgorithmMethod algorithm, DigestMethod digest) {
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

    public NameIDPolicy getNameIDPolicy() {
        return nameIDPolicy;
    }

    public AuthenticationRequest setNameIDPolicy(NameIDPolicy nameIDPolicy) {
        this.nameIDPolicy = nameIDPolicy;
        return _this();
    }
}
