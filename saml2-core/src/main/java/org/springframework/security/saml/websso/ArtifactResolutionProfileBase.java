/*
 * Copyright 2010 Mandus Elfving, Vladimir Sch�fer
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
package org.springframework.security.saml.websso;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.util.Base64;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.util.SAMLUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Base implementation of the artifactResolution profile. Subclasses need to implement sending of ArtifactRequest
 * using custom transport and retrieving the ArtifactResponse.
 */
public abstract class ArtifactResolutionProfileBase extends AbstractProfileBase implements ArtifactResolutionProfile {

    /**
     * Creates ArtifactResolve message based in the artifactId, locates ArtifactResolutionService, populates SAMLContext
     * and performs artifact retrieval. Message included in the response is returned.
     *
     * @param artifactId artifact to resolve
     * @param endpointURI URI of the endpoint the message was sent to
     * @return message from the resolve artifact
     * @throws MessageDecodingException error decoding the artifact
     */
    public SAMLObject resolveArtifact(String artifactId, String endpointURI) throws MessageDecodingException {

        // Decode artifact.
        SAML2ArtifactType0004 decodedArtifact = new SAML2ArtifactType0004Builder().buildArtifact(Base64.decode(artifactId));

        // Endpoint index.
        int endpointIndex = parseEndpointIndex(decodedArtifact.getEndpointIndex());

        EntityDescriptor idpEntityDescriptor = getIDPEntityDescriptor(metadata, decodedArtifact);
        IDPSSODescriptor idpssoDescriptor = SAMLUtil.getIDPSSODescriptor(idpEntityDescriptor);
        ArtifactResolutionService artifactResolutionService = SAMLUtil.getArtifactResolutionService(idpssoDescriptor, endpointIndex);

        // Create SAML message for artifact resolution
        ArtifactResolve artifactResolve = createArtifactResolve(artifactId, artifactResolutionService);

        try {

            BasicSAMLMessageContext context = new BasicSAMLMessageContext();

            context.setCommunicationProfileId(artifactResolutionService.getBinding());
            context.setOutboundMessage(artifactResolve);
            context.setOutboundSAMLMessage(artifactResolve);
            context.setPeerEntityEndpoint(artifactResolutionService);
            context.setPeerEntityId(idpEntityDescriptor.getID());
            context.setPeerEntityMetadata(idpEntityDescriptor);
            context.setPeerEntityRole(idpssoDescriptor.getElementQName());
            context.setPeerEntityRoleMetadata(idpssoDescriptor);

            getArtifactResponse(endpointURI, context);

            ArtifactResponse artifactResponse = (ArtifactResponse) context.getInboundSAMLMessage();

            if (artifactResponse == null) {
                log.debug("Did not receive an artifact response message.");
                throw new MessageDecodingException("Did not receive an artifact response message.");
            }

            SAMLObject message = artifactResponse.getMessage();
            if (message == null) {
                log.debug("No inbound message in artifact response message.");
                throw new MessageDecodingException("No inbound message in artifact response message.");
            }

            return message;

        } catch (MetadataProviderException mee) {
            log.debug("Error processing meatadata.", mee);
            throw new MessageDecodingException("Error processing metadata.", mee);
        } catch (MessageEncodingException mee) {
            log.debug("Could not encode artifact resolve message.", mee);
            throw new MessageDecodingException("Could not encode artifact resolve message.", mee);
        } catch (MessageDecodingException e) {
            log.debug("Could not decode artifact response message.", e);
            throw new MessageDecodingException("Could not decode artifact response message.", e);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.debug("Security error when decoding artifact response message.", e);
            throw new MessageDecodingException("Security error when decoding artifact response message.", e);
        } catch (SAMLException e) {
            log.debug("Error during message processing.", e);
            throw new MessageDecodingException("Error during message processing.", e);
        }

    }

    /**
     * Method is expected to send ArtifactRequest to the artifactResolution service and store the ArtifactResponse.
     * InboundMessageTransport and OutboundMessageTransport in the context need to be filled.
     *
     * @param endpointURI URI incoming artifactMessage is addressed to
     * @param context     context with filled communicationProfileId, outboundMessage, outboundSAMLMessage, peerEntityEndpoint, peerEntityId, peerEntityMetadata, peerEntityRole, peerEntityRoleMetadata
     * @throws org.opensaml.common.SAMLException             error processing artifact messages
     * @throws org.opensaml.ws.message.encoder.MessageEncodingException  error sending artifactRequest
     * @throws org.opensaml.ws.message.decoder.MessageDecodingException  error retrieveing articatResponse
     * @throws org.opensaml.saml2.metadata.provider.MetadataProviderException error resolving metadata
     * @throws org.opensaml.xml.security.SecurityException invalid message signature
     */
    protected abstract void getArtifactResponse(String endpointURI, BasicSAMLMessageContext context) throws SAMLException, MessageEncodingException, MessageDecodingException, MetadataProviderException, org.opensaml.xml.security.SecurityException;

    protected ArtifactResolve createArtifactResolve(String artifactId, Endpoint endpoint) {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        SAMLObjectBuilder<Artifact> artifactBuilder = (SAMLObjectBuilder<Artifact>) builderFactory.getBuilder(Artifact.DEFAULT_ELEMENT_NAME);
        SAMLObjectBuilder<ArtifactResolve> artifactResolveBuilder = (SAMLObjectBuilder<ArtifactResolve>) builderFactory.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);

        Artifact artifact = artifactBuilder.buildObject();
        artifact.setArtifact(artifactId);

        ArtifactResolve artifactResolve = artifactResolveBuilder.buildObject();
        artifactResolve.setArtifact(artifact);

        buildCommonAttributes(artifactResolve, endpoint);

        return artifactResolve;

    }

    private int parseEndpointIndex(byte[] endpointIndexBytes) {

        int endpointIndex = 0;

        for (int i = 0; i < endpointIndexBytes.length; i++) {
            endpointIndex = (endpointIndex << (i * 4)) | endpointIndexBytes[i];
        }

        return endpointIndex;

    }

    private EntityDescriptor getIDPEntityDescriptor(MetadataProvider metadataProvider, SAML2ArtifactType0004 decodedArtifact) throws MessageDecodingException {

        EntityDescriptor idpEntityDescriptor;

        try {
            XMLObject xmlObject = metadataProvider.getMetadata();
            idpEntityDescriptor = getEntityDescriptor(xmlObject, decodedArtifact.getSourceID());
        } catch (MetadataProviderException mpe) {
            log.debug("Could not read metadata from metadata provider.");
            throw new MessageDecodingException("Could not read metadata from metadata provider.", mpe);
        } catch (NoSuchAlgorithmException nsae) {
            log.error("SHA1 algorithm is not supported.", nsae);
            throw new MessageDecodingException("SHA1 algorithm is not supported.", nsae);
        }

        if (idpEntityDescriptor == null) {
            log.error("Could not find an entity descriptor in metadata.");
            throw new MessageDecodingException("Could not find an entity descriptor in metadata.");
        }

        return idpEntityDescriptor;

    }

    private EntityDescriptor getEntityDescriptor(XMLObject xmlObject, byte[] sourceID) throws NoSuchAlgorithmException {

        if (xmlObject instanceof EntityDescriptor) {

            EntityDescriptor entityDescriptor = (EntityDescriptor) xmlObject;
            return checkIfArtifactReferencesEntityDescriptor(entityDescriptor, sourceID) ? entityDescriptor : null;

        } else if (xmlObject instanceof EntitiesDescriptor) {

            EntitiesDescriptor entitiesDescriptor = (EntitiesDescriptor) xmlObject;

            for (EntityDescriptor ed : entitiesDescriptor.getEntityDescriptors()) {
                if (checkIfArtifactReferencesEntityDescriptor(ed, sourceID)) {
                    log.debug("Found EntityDescriptor: {}", ed);
                    return ed;
                }
            }

            for (EntitiesDescriptor ed : entitiesDescriptor.getEntitiesDescriptors()) {
                EntityDescriptor entityDescriptor = getEntityDescriptor(ed, sourceID);
                if (entityDescriptor != null) {
                    return entityDescriptor;
                }
            }
        }

        return null;

    }

    private boolean checkIfArtifactReferencesEntityDescriptor(EntityDescriptor entityDescriptor, byte[] sourceID) throws NoSuchAlgorithmException {

        MessageDigest sha1Digester = MessageDigest.getInstance("SHA-1");
        byte[] hashedEntityId = sha1Digester.digest(entityDescriptor.getEntityID().getBytes());

        for (int i = 0; i < hashedEntityId.length; i++) {
            if (hashedEntityId[i] != sourceID[i]) {
                return false;
            }
        }

        return true;

    }

}