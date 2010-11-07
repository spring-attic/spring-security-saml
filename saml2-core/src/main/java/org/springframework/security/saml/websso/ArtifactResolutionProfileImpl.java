/*
 * Copyright 2010 Vladimir Schaefer
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

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.opensaml.common.SAMLException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpClientInTransport;
import org.opensaml.ws.transport.http.HttpClientOutTransport;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;

import java.io.IOException;

/**
 * Implementation of the artifact resolution protocol which uses Apache HTTPClient for SOAP binding transport.
 */
public class ArtifactResolutionProfileImpl extends ArtifactResolutionProfileBase {

    private HttpClient httpClient;

    /**
     * @param httpClient client used to send SOAP messages
     */
    public ArtifactResolutionProfileImpl(SAMLProcessor processor, MetadataManager metadata, KeyManager keyManager, SAMLArtifactMap artifactMap, HttpClient httpClient) {
        super(processor, metadata, keyManager, artifactMap);
        this.httpClient = httpClient;
    }

    /**
     * Uses HTTPClient to send and retrieve ArtifactMessages. 
     *
     * @param endpointURI URI incoming artifactMessage is addressed to
     * @param context     context with filled communicationProfileId, outboundMessage, outboundSAMLMessage, peerEntityEndpoint, peerEntityId, peerEntityMetadata, peerEntityRole, peerEntityRoleMetadata
     * @throws SAMLException             error processing artifact messages
     * @throws MessageEncodingException  error sending artifactRequest
     * @throws MessageDecodingException  error retrieveing articatResponse
     * @throws MetadataProviderException error resolving metadata
     * @throws org.opensaml.xml.security.SecurityException invalid message signature
     */
    protected void getArtifactResponse(String endpointURI, BasicSAMLMessageContext context) throws SAMLException, MessageEncodingException, MessageDecodingException, MetadataProviderException, org.opensaml.xml.security.SecurityException {

        PostMethod postMethod = null;

        try {

            postMethod = new PostMethod(context.getPeerEntityEndpoint().getLocation());

            HttpClientOutTransport clientOutTransport = new HttpClientOutTransport(postMethod);
            HttpClientInTransport clientInTransport = new HttpClientInTransport(postMethod, endpointURI);

            context.setInboundMessageTransport(clientInTransport);
            context.setOutboundMessageTransport(clientOutTransport);

            // Send artifact retrieve message
            processor.sendMessage(context, true);

            int responseCode = httpClient.executeMethod(postMethod);
            if (responseCode != 200) {
                log.debug("Problem communicating with Artifact Resolution service, received response {}.", responseCode);
                throw new MessageDecodingException("Problem communicating with Artifact Resolution service, received response " + responseCode);
            }

            // Decode artifact response message.
            processor.retrieveMessage(context, SAMLConstants.SAML2_SOAP11_BINDING_URI);

        } catch (IOException e) {

            log.debug("Error when sending request to artifact resolution service.", e);
            throw new MessageDecodingException("Error when sending request to artifact resolution service.", e);

        } finally {

            if (postMethod != null) {
                postMethod.releaseConnection();
            }

        }

    }

}