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
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.trust.TrustEngine;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.storage.SAMLMessageStorage;

import javax.net.ssl.HostnameVerifier;

/**
 * Message context with Spring Extension SAML module specific values.
 *
 * @author Vladimir Schaefer
 */
public class SAMLMessageContext extends BasicSAMLMessageContext {

    private Decrypter localDecrypter;
    private Credential localSigningCredential;
    private ExtendedMetadata localExtendedMetadata;
    private SignatureTrustEngine localTrustEngine;
    private TrustEngine<X509Credential> localSSLTrustEngine;
    private X509Credential localSSLCredential;
    private HostnameVerifier localSSLHostnameVerifier;
    private Endpoint localEntityEndpoint;
    private X509Credential peerSSLCredential;
    private ExtendedMetadata peerExtendedMetadata;
    private boolean peerUserSelected;
    private String inboundSAMLBinding;
    private SAMLMessageStorage messageStorage;

    /**
     * Extended metadata of the local entity
     *
     * @return local extended metadata
     */
    public ExtendedMetadata getLocalExtendedMetadata() {
        return localExtendedMetadata;
    }

    public void setLocalExtendedMetadata(ExtendedMetadata localExtendedMetadata) {
        this.localExtendedMetadata = localExtendedMetadata;
    }

    /**
     * Extended metadata of the peer entity.
     *
     * @return metadata
     */
    public ExtendedMetadata getPeerExtendedMetadata() {
        return peerExtendedMetadata;
    }

    public void setPeerExtendedMetadata(ExtendedMetadata peerExtendedMetadata) {
        this.peerExtendedMetadata = peerExtendedMetadata;
    }

    /**
     * Object capable of decrypting data signed for this entity.
     *
     * @return decrypter
     */
    public Decrypter getLocalDecrypter() {
        return localDecrypter;
    }

    public void setLocalDecrypter(Decrypter localDecrypter) {
        this.localDecrypter = localDecrypter;
    }

    /**
     * Mechanism able to determine whether incoming message signature should be trusted.
     *
     * @return trust engine used for verification of signatures coming from peers
     */
    public SignatureTrustEngine getLocalTrustEngine() {
        return localTrustEngine;
    }

    public void setLocalTrustEngine(SignatureTrustEngine localTrustEngine) {
        this.localTrustEngine = localTrustEngine;
    }

    /**
     * Credential used to sign messages sent from this entity.
     *
     * @return credential
     */
    public Credential getLocalSigningCredential() {
        return localSigningCredential;
    }

    public void setLocalSigningCredential(Credential localSigningCredential) {
        this.localSigningCredential = localSigningCredential;
    }

    /**
     * Trust engine used to verify server certificate in SSL/TLS connections.
     *
     * @return engine
     */
    public TrustEngine<X509Credential> getLocalSSLTrustEngine() {
        return localSSLTrustEngine;
    }

    public void setLocalSSLTrustEngine(TrustEngine<X509Credential> localSSLTrustEngine) {
        this.localSSLTrustEngine = localSSLTrustEngine;
    }

    /**
     * Credential used to authenticate this instance against peers using SSL/TLS .
     *
     * @return credential
     */
    public X509Credential getLocalSSLCredential() {
        return localSSLCredential;
    }

    public void setLocalSSLCredential(X509Credential localSSLCredential) {
        this.localSSLCredential = localSSLCredential;
    }

    /**
     * Verifier used to verify hostname when making connections using HTTPS (e.g. during Artifact
     * resolution.
     *
     * @return hostname verifier, or null to skip hostname verification
     */
    public HostnameVerifier getLocalSSLHostnameVerifier() {
        return localSSLHostnameVerifier;
    }

    public void setGetLocalSSLHostnameVerifier(HostnameVerifier verifier) {
        this.localSSLHostnameVerifier = verifier;
    }

    /**
     * Certificate used the peer entity used to authenticate against our server as part of the SSL/TLS
     * connection. Only used for peer initiated communication.
     *
     * @return peer credential, when available
     */
    public X509Credential getPeerSSLCredential() {
        return peerSSLCredential;
    }

    public void setPeerSSLCredential(X509Credential peerSSLCredential) {
        this.peerSSLCredential = peerSSLCredential;
    }

    /**
     * Binding used to deliver the current message.
     *
     * @return incoming binding
     */
    public String getInboundSAMLBinding() {
        return inboundSAMLBinding;
    }

    /**
     * Binding used to deliver the current message.
     *
     * @param inboundSAMLBinding binding
     */
    public void setInboundSAMLBinding(String inboundSAMLBinding) {
        this.inboundSAMLBinding = inboundSAMLBinding;
    }

    /**
     * Endpoint the incoming message (if any) was received at.
     *
     * @return endpoint for incoming messages, null otherwise
     */
    public Endpoint getLocalEntityEndpoint() {
        return localEntityEndpoint;
    }

    public void setLocalEntityEndpoint(Endpoint localEntityEndpoint) {
        this.localEntityEndpoint = localEntityEndpoint;
    }

    /**
     * Determines whether the peer entity was determined automatically (e.g. using defaults) or whether
     * it's a result of explicit user selection.
     *
     * @return true if peer (IDP) was chosen by user
     */
    public boolean isPeerUserSelected() {
        return peerUserSelected;
    }

    public void setPeerUserSelected(boolean peerUserSelected) {
        this.peerUserSelected = peerUserSelected;
    }

    /**
     * Storage messages sent during processing of this context.
     *
     * @return message storage, null if sent messages cannot be stored
     */
    public SAMLMessageStorage getMessageStorage() {
        return messageStorage;
    }

    /**
     * Sets message storage for this context.
     *
     * @param messageStorage message storage or null if storing of messages isn't supported
     */
    public void setMessageStorage(SAMLMessageStorage messageStorage) {
        this.messageStorage = messageStorage;
    }

}