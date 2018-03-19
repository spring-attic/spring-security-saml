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

package org.opensaml.compat;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.compat.security.SecurityPolicyResolver;
import org.opensaml.compat.transport.InTransport;
import org.opensaml.compat.transport.OutTransport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.credential.Credential;

public class BackwardsCompatibleMessageContext<T> extends MessageContext<T>  {

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
    private XMLObject outboundMessage;
    private SAMLObject outboundSAMLMessage;
    private Endpoint peerEntityEndpoint;
    private InTransport inboundMessageTransport;
    private OutTransport outboundMessageTransport;
    private String relayState;
    private SAMLObject inboundSAMLMessage;
    private String inboundSAMLProtocol;
    private String inboundMessageIssuer;
    private Credential outboundSAMLMessageSigningCredential;
    private boolean issuerAuthenticated;
    private boolean inboundSAMLMessageAuthenticated;
    private DateTime inboundSAMLMessageIssueInstant;
    private String inboundSAMLMessageId;
    private SecurityPolicyResolver securityPolicyResolver;
    private NameID subjectNameIdentifier;
    private XMLObject inboundMessage;

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

    public String getCommunicationProfileId() {
        return communicationProfileId;
    }

    public void setCommunicationProfileId(String communicationProfileId) {
        this.communicationProfileId = communicationProfileId;
    }

    public XMLObject getOutboundMessage() {
        return outboundMessage;
    }

    public void setOutboundMessage(XMLObject outboundMessage) {
        this.outboundMessage = outboundMessage;
    }

    public SAMLObject getOutboundSAMLMessage() {
        return outboundSAMLMessage;
    }

    public void setOutboundSAMLMessage(SAMLObject outboundSAMLMessage) {
        this.outboundSAMLMessage = outboundSAMLMessage;
    }

    public Endpoint getPeerEntityEndpoint() {
        return peerEntityEndpoint;
    }

    public void setPeerEntityEndpoint(Endpoint peerEntityEndpoint) {
        this.peerEntityEndpoint = peerEntityEndpoint;
    }

    public InTransport getInboundMessageTransport() {
        return inboundMessageTransport;
    }

    public void setInboundMessageTransport(InTransport inboundMessageTransport) {
        this.inboundMessageTransport = inboundMessageTransport;
    }

    public OutTransport getOutboundMessageTransport() {
        return outboundMessageTransport;
    }

    public void setOutboundMessageTransport(OutTransport outboundMessageTransport) {
        this.outboundMessageTransport = outboundMessageTransport;
    }

    public String getRelayState() {
        return relayState;
    }

    public void setRelayState(String relayState) {
        this.relayState = relayState;
    }

    public SAMLObject getInboundSAMLMessage() {
        return inboundSAMLMessage;
    }

    public void setInboundSAMLMessage(SAMLObject inboundSAMLMessage) {
        this.inboundSAMLMessage = inboundSAMLMessage;
    }

    public String getInboundSAMLProtocol() {
        return inboundSAMLProtocol;
    }

    public void setInboundSAMLProtocol(String inboundSAMLProtocol) {
        this.inboundSAMLProtocol = inboundSAMLProtocol;
    }

    public String getInboundMessageIssuer() {
        return inboundMessageIssuer;
    }

    public void setInboundMessageIssuer(String inboundMessageIssuer) {
        this.inboundMessageIssuer = inboundMessageIssuer;
    }

    public Credential getOutboundSAMLMessageSigningCredential() {
        return outboundSAMLMessageSigningCredential;
    }

    public void setOutboundSAMLMessageSigningCredential(Credential outboundSAMLMessageSigningCredential) {
        this.outboundSAMLMessageSigningCredential = outboundSAMLMessageSigningCredential;
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

    public DateTime getInboundSAMLMessageIssueInstant() {
        return inboundSAMLMessageIssueInstant;
    }

    public void setInboundSAMLMessageIssueInstant(DateTime inboundSAMLMessageIssueInstant) {
        this.inboundSAMLMessageIssueInstant = inboundSAMLMessageIssueInstant;
    }

    public String getInboundSAMLMessageId() {
        return inboundSAMLMessageId;
    }

    public void setInboundSAMLMessageId(String inboundSAMLMessageId) {
        this.inboundSAMLMessageId = inboundSAMLMessageId;
    }

    public SecurityPolicyResolver getSecurityPolicyResolver() {
        return securityPolicyResolver;
    }

    public void setSecurityPolicyResolver(SecurityPolicyResolver securityPolicyResolver) {
        this.securityPolicyResolver = securityPolicyResolver;
    }

    public NameID getSubjectNameIdentifier() {
        return subjectNameIdentifier;
    }

    public void setSubjectNameIdentifier(NameID subjectNameIdentifier) {
        this.subjectNameIdentifier = subjectNameIdentifier;
    }

    public XMLObject getInboundMessage() {
        return inboundMessage;
    }

    public void setInboundMessage(XMLObject inboundMessage) {
        this.inboundMessage = inboundMessage;
    }
}
