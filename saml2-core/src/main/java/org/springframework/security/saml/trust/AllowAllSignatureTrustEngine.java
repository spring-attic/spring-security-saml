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
package org.springframework.security.saml.trust;

import org.opensaml.xml.security.*;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;

/**
 * Special type of trust engine which always trusts the credential and thus skips the verification.
 */
public class AllowAllSignatureTrustEngine implements SignatureTrustEngine {

    private KeyInfoCredentialResolver keyInfoResolver;

    public AllowAllSignatureTrustEngine(KeyInfoCredentialResolver keyInfoResolver) {
        this.keyInfoResolver = keyInfoResolver;
    }

    public KeyInfoCredentialResolver getKeyInfoResolver() {
        return keyInfoResolver;
    }

    public boolean validate(byte[] signature, byte[] content, String algorithmURI, CriteriaSet trustBasisCriteria, Credential candidateCredential) throws org.opensaml.xml.security.SecurityException {
        return true;
    }

    public boolean validate(Signature token, CriteriaSet trustBasisCriteria) throws SecurityException {
        return true;
    }

}
