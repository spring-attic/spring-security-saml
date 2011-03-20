/*
 * Copyright 2011 Vladimir Schaefer
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
package org.springframework.security.saml.context;

import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.metadata.ExtendedMetadata;

/**
 * Message context with Spring Extension SAML module specific values.
 *
 * @author Vladimir Schaefer
 */
public class SAMLMessageContext extends BasicSAMLMessageContext {

    /**
     * Object capable of decrypting data signed for this entity.
     */
    private Decrypter localDecrypter;

    /**
     * Credential used to sign messages sent from this entity.
     */
    private Credential localSigningCredential;

    /**
     * Extended metadata of the local entity
     */
    private ExtendedMetadata localExtendedMetadata;

    /**
     * Extended metadata of the peer entity
     */
    private ExtendedMetadata peerExtendedMetadata;

    /**
     * Mechanism able to determine whether incoming message signature should be trusted.
     */
    private SignatureTrustEngine localTrustEngine;

    public ExtendedMetadata getLocalExtendedMetadata() {
        return localExtendedMetadata;
    }

    public void setLocalExtendedMetadata(ExtendedMetadata localExtendedMetadata) {
        this.localExtendedMetadata = localExtendedMetadata;
    }

    public ExtendedMetadata getPeerExtendedMetadata() {
        return peerExtendedMetadata;
    }

    public void setPeerExtendedMetadata(ExtendedMetadata peerExtendedMetadata) {
        this.peerExtendedMetadata = peerExtendedMetadata;
    }

    public Decrypter getLocalDecrypter() {
        return localDecrypter;
    }

    public void setLocalDecrypter(Decrypter localDecrypter) {
        this.localDecrypter = localDecrypter;
    }

    public SignatureTrustEngine getLocalTrustEngine() {
        return localTrustEngine;
    }

    public void setLocalTrustEngine(SignatureTrustEngine localTrustEngine) {
        this.localTrustEngine = localTrustEngine;
    }

    public Credential getLocalSigningCredential() {
        return localSigningCredential;
    }

    public void setLocalSigningCredential(Credential localSigningCredential) {
        this.localSigningCredential = localSigningCredential;
    }

}