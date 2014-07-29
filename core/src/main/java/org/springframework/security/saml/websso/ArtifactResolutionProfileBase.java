/*
 * Copyright 2010 Mandus Elfving, Vladimir Schaefer
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

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.util.Base64;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.util.SAMLUtil;

import static org.springframework.security.saml.util.SAMLUtil.isDateTimeSkewValid;

/**
 * Base implementation of the artifactResolution profile. Subclasses need to implement sending of ArtifactRequest
 * using custom transport and retrieving the ArtifactResponse.
 *
 * @author Vladimir Schaefer
 */
public abstract class ArtifactResolutionProfileBase extends AbstractProfileBase implements ArtifactResolutionProfile {

    @Override
    public String getProfileIdentifier() {
        return org.springframework.security.saml.SAMLConstants.SAML2_ARTIFACT_PROFILE_URI;
    }

    /**
     * Creates ArtifactResolve message based in the artifactId, locates ArtifactResolutionService, populates SAMLContext
     * and performs artifact retrieval. Message included in the response is returned.
     *
     * @param context     context containing information about local SP/IDP entity
     * @param artifactId  artifact to resolve
     * @param endpointURI URI of the endpoint the message was sent to
     * @return message from the resolve artifact
     * @throws MessageDecodingException error decoding the artifact
     */
    public SAMLObject resolveArtifact(SAMLMessageContext context, String artifactId, String endpointURI) throws MessageDecodingException {

        try {

            // Decode artifact.
            SAML2ArtifactType0004 decodedArtifact = new SAML2ArtifactType0004Builder().buildArtifact(Base64.decode(artifactId));

            // Endpoint index.
            int endpointIndex = parseEndpointIndex(decodedArtifact.getEndpointIndex());

            // Locate sender using the artifact sourceID
            EntityDescriptor idpEntityDescriptor = metadata.getEntityDescriptor(decodedArtifact.getSourceID());

            if (idpEntityDescriptor == null) {
                throw new MetadataProviderException("Cannot localize sender entity by SHA-1 hash from the artifact");
            }

            ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(idpEntityDescriptor.getEntityID());
            IDPSSODescriptor idpssoDescriptor = SAMLUtil.getIDPSSODescriptor(idpEntityDescriptor);
            ArtifactResolutionService artifactResolutionService = SAMLUtil.getArtifactResolutionService(idpssoDescriptor, endpointIndex);

            // Create SAML message for artifact resolution
            ArtifactResolve artifactResolve = createArtifactResolve(context, artifactId, artifactResolutionService);

            context.setCommunicationProfileId(getProfileIdentifier());
            context.setInboundSAMLBinding(artifactResolutionService.getBinding());
            context.setOutboundMessage(artifactResolve);
            context.setOutboundSAMLMessage(artifactResolve);
            context.setPeerEntityEndpoint(artifactResolutionService);
            context.setPeerEntityId(idpEntityDescriptor.getEntityID());
            context.setPeerEntityMetadata(idpEntityDescriptor);
            context.setPeerEntityRole(idpssoDescriptor.getElementQName());
            context.setPeerEntityRoleMetadata(idpssoDescriptor);
            context.setPeerExtendedMetadata(extendedMetadata);

            getArtifactResponse(endpointURI, context);

            ArtifactResponse artifactResponse = (ArtifactResponse) context.getInboundSAMLMessage();

            if (artifactResponse == null) {
                throw new MessageDecodingException("Did not receive an artifact response message.");
            }

            DateTime issueInstant = artifactResponse.getIssueInstant();
            if (!isDateTimeSkewValid(getResponseSkew(), issueInstant)) {
                throw new MessageDecodingException("ArtifactResponse issue time is either too old or with date in the future, skew " + getResponseSkew() + ", time " + issueInstant);
            }

            SAMLObject message = artifactResponse.getMessage();
            if (message == null) {
                throw new MessageDecodingException("No inbound message in artifact response message.");
            }

            return message;

        } catch (MetadataProviderException e) {
            throw new MessageDecodingException("Error processing metadata", e);
        } catch (MessageEncodingException e) {
            throw new MessageDecodingException("Could not encode artifact resolve message", e);
        } catch (MessageDecodingException e) {
            throw new MessageDecodingException("Could not decode artifact response message", e);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new MessageDecodingException("Security error when decoding artifact response message", e);
        } catch (SAMLException e) {
            throw new MessageDecodingException("Error during message processing", e);
        }

    }

    /**
     * Method is expected to send ArtifactRequest to the artifactResolution service and store the ArtifactResponse.
     * InboundMessageTransport and OutboundMessageTransport in the context need to be filled by the implementation, the
     * rest of the context is already available.
     *
     * @param endpointURI URI incoming artifactMessage is addressed to
     * @param context     context with filled communicationProfileId, outboundMessage, outboundSAMLMessage, peerEntityEndpoint, peerEntityId, peerEntityMetadata, peerEntityRole, peerEntityRoleMetadata
     * @throws org.opensaml.common.SAMLException
     *          error processing artifact messages
     * @throws org.opensaml.ws.message.encoder.MessageEncodingException
     *          error sending artifactRequest
     * @throws org.opensaml.ws.message.decoder.MessageDecodingException
     *          error retrieveing articatResponse
     * @throws org.opensaml.saml2.metadata.provider.MetadataProviderException
     *          error resolving metadata
     * @throws org.opensaml.xml.security.SecurityException
     *          invalid message signature
     */
    protected abstract void getArtifactResponse(String endpointURI, SAMLMessageContext context) throws SAMLException, MessageEncodingException, MessageDecodingException, MetadataProviderException, org.opensaml.xml.security.SecurityException;

    protected ArtifactResolve createArtifactResolve(SAMLMessageContext context, String artifactId, Endpoint endpoint) {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        SAMLObjectBuilder<Artifact> artifactBuilder = (SAMLObjectBuilder<Artifact>) builderFactory.getBuilder(Artifact.DEFAULT_ELEMENT_NAME);
        SAMLObjectBuilder<ArtifactResolve> artifactResolveBuilder = (SAMLObjectBuilder<ArtifactResolve>) builderFactory.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);

        Artifact artifact = artifactBuilder.buildObject();
        artifact.setArtifact(artifactId);

        ArtifactResolve artifactResolve = artifactResolveBuilder.buildObject();
        artifactResolve.setArtifact(artifact);

        buildCommonAttributes(context.getLocalEntityId(), artifactResolve, endpoint);

        return artifactResolve;

    }

    private int parseEndpointIndex(byte[] endpointIndexBytes) {

        int endpointIndex = 0;

        for (int i = 0; i < endpointIndexBytes.length; i++) {
            endpointIndex = (endpointIndex << (i * 4)) | endpointIndexBytes[i];
        }

        return endpointIndex;

    }

}