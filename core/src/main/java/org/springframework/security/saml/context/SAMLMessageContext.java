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

import javax.net.ssl.HostnameVerifier;
import javax.xml.namespace.QName;

import org.opensaml.compat.MetadataProvider;
import org.opensaml.compat.transport.InTransport;
import org.opensaml.compat.transport.OutTransport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.storage.SAMLMessageStorage;

/**
 * Message context with Spring Extension SAML module specific values.
 *
 * @author Vladimir Schaefer
 */
public class SAMLMessageContext extends MessageContext {

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

    //backwards compatible fields
    private EntityDescriptor peerEntityMetadata;
    private RoleDescriptor peerEntityRoleMetadata;
    private String peerEntityId;
    private QName peerEntityRole;

    private String localEntityId;
    private EntityDescriptor localEntityMetadata;
    private QName localEntityRole;
    private RoleDescriptor localEntityRoleMetadata;


    private MetadataProvider metadataProvider;
    private InTransport inboundTransport;
    private String communicationProfileId;
    private ArtifactResolve outboundMessage;
    private ArtifactResolve outboundSAMLMessage;
    private ArtifactResolutionService peerEntityEndpoint;
    private InTransport inboundMessageTransport;
    private OutTransport outboundMessageTransport;
    private String relayState;
    private SAMLObject inboundSAMLMessage;
    private String inboundSAMLProtocol;
    private String inboundMessageIssuer;
    private Credential outboundSAMLMessageSigningCredential;
    private boolean issuerAuthenticated;
    private boolean inboundSAMLMessageAuthenticated;


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

    public EntityDescriptor getPeerEntityMetadata() {
        return peerEntityMetadata;
    }

    public void setPeerEntityMetadata(EntityDescriptor peerEntityMetadata) {
        this.peerEntityMetadata = peerEntityMetadata;
    }

    public RoleDescriptor getPeerEntityRoleMetadata() {
        return peerEntityRoleMetadata;
    }

    public void setPeerEntityRoleMetadata(RoleDescriptor peerEntityRoleMetadata) {
        this.peerEntityRoleMetadata = peerEntityRoleMetadata;
    }

    public String getPeerEntityId() {
        return peerEntityId;
    }

    public void setPeerEntityId(String peerEntityId) {
        this.peerEntityId = peerEntityId;
    }

    public QName getPeerEntityRole() {
        return peerEntityRole;
    }

    public void setPeerEntityRole(QName peerEntityRole) {
        this.peerEntityRole = peerEntityRole;
    }

    public MetadataProvider getMetadataProvider() {
        return metadataProvider;
    }

    public void setMetadataProvider(MetadataProvider metadataProvider) {
        this.metadataProvider = metadataProvider;
    }

    public InTransport getInboundTransport() {
        return inboundTransport;
    }

    public void setInboundTransport(InTransport inboundTransport) {
        this.inboundTransport = inboundTransport;
    }

    public String getLocalEntityId() {
        return localEntityId;
    }

    public void setLocalEntityId(String localEntityId) {
        this.localEntityId = localEntityId;
    }

    public EntityDescriptor getLocalEntityMetadata() {
        return localEntityMetadata;
    }

    public void setLocalEntityMetadata(EntityDescriptor localEntityMetadata) {
        this.localEntityMetadata = localEntityMetadata;
    }

    public QName getLocalEntityRole() {
        return localEntityRole;
    }

    public void setLocalEntityRole(QName localEntityRole) {
        this.localEntityRole = localEntityRole;
    }

    public RoleDescriptor getLocalEntityRoleMetadata() {
        return localEntityRoleMetadata;
    }

    public void setLocalEntityRoleMetadata(RoleDescriptor localEntityRoleMetadata) {
        this.localEntityRoleMetadata = localEntityRoleMetadata;
    }

    public void setCommunicationProfileId(String communicationProfileId) {
        this.communicationProfileId = communicationProfileId;
    }

    public String getCommunicationProfileId() {
        return communicationProfileId;
    }

    public void setOutboundMessage(ArtifactResolve outboundMessage) {
        this.outboundMessage = outboundMessage;
    }

    public ArtifactResolve getOutboundMessage() {
        return outboundMessage;
    }

    public void setOutboundSAMLMessage(ArtifactResolve outboundSAMLMessage) {
        this.outboundSAMLMessage = outboundSAMLMessage;
    }

    public ArtifactResolve getOutboundSAMLMessage() {
        return outboundSAMLMessage;
    }

    public void setPeerEntityEndpoint(ArtifactResolutionService peerEntityEndpoint) {
        this.peerEntityEndpoint = peerEntityEndpoint;
    }

    public ArtifactResolutionService getPeerEntityEndpoint() {
        return peerEntityEndpoint;
    }

    public InTransport getInboundMessageTransport() {
        return inboundMessageTransport;
    }

    public void setInboundMessageTransport(InTransport inboundMessageTransport) {
        this.inboundMessageTransport = inboundMessageTransport;
    }

    public void setOutboundMessageTransport(OutTransport outboundMessageTransport) {
        this.outboundMessageTransport = outboundMessageTransport;
    }

    public OutTransport getOutboundMessageTransport() {
        return outboundMessageTransport;
    }

    public void setRelayState(String relayState) {
        this.relayState = relayState;
    }

    public String getRelayState() {
        return relayState;
    }

    public void setInboundSAMLMessage(SAMLObject inboundSAMLMessage) {
        this.inboundSAMLMessage = inboundSAMLMessage;
    }

    public SAMLObject getInboundSAMLMessage() {
        return inboundSAMLMessage;
    }

    public void setInboundSAMLProtocol(String inboundSAMLProtocol) {
        this.inboundSAMLProtocol = inboundSAMLProtocol;
    }

    public String getInboundSAMLProtocol() {
        return inboundSAMLProtocol;
    }

    public String getInboundMessageIssuer() {
        return inboundMessageIssuer;
    }

    public void setInboundMessageIssuer(String inboundMessageIssuer) {
        this.inboundMessageIssuer = inboundMessageIssuer;
    }

    public void setOutboundSAMLMessageSigningCredential(Credential outboundSAMLMessageSigningCredential) {
        this.outboundSAMLMessageSigningCredential = outboundSAMLMessageSigningCredential;
    }

    public Credential getOutboundSAMLMessageSigningCredential() {
        return outboundSAMLMessageSigningCredential;
    }

    public boolean isIssuerAuthenticated() {
        return issuerAuthenticated;
    }

    public void setIssuerAuthenticated(boolean issuerAuthenticated) {
        this.issuerAuthenticated = issuerAuthenticated;
    }

    public boolean isInboundSAMLMessageAuthenticated() {
        return inboundSAMLMessageAuthenticated;
    }

    public void setInboundSAMLMessageAuthenticated(boolean inboundSAMLMessageAuthenticated) {
        this.inboundSAMLMessageAuthenticated = inboundSAMLMessageAuthenticated;
    }
}