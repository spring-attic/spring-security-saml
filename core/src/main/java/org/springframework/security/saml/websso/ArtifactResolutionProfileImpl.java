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

import javax.net.ssl.HostnameVerifier;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.spy.memcached.ConnectionFactoryBuilder;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.opensaml.compat.MetadataCriteria;
import org.opensaml.compat.MetadataProviderException;
import org.opensaml.compat.UsageCriteria;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.UsageType;
import org.opensaml.ws.transport.http.HttpClientInTransport;
import org.opensaml.ws.transport.http.HttpClientOutTransport;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.trust.X509KeyManager;
import org.springframework.security.saml.trust.X509TrustManager;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;

/**
 * Implementation of the artifact resolution protocol which uses Apache HTTPClient for SOAP binding transport.
 */
public class ArtifactResolutionProfileImpl extends ArtifactResolutionProfileBase {

    /**
     * Client used to perform HTTP calls for artifact resolution.
     */
    private HttpClient httpClient;

    /**
     * @param httpClient client used to send SOAP messages
     */
    public ArtifactResolutionProfileImpl() {

    }

    /**
     * Uses HTTPClient to send and retrieve ArtifactMessages.
     *
     * @param endpointURI URI incoming artifactMessage is addressed to
     * @param context     context with filled communicationProfileId, outboundMessage, outboundSAMLMessage, peerEntityEndpoint, peerEntityId, peerEntityMetadata, peerEntityRole, peerEntityRoleMetadata
     * @throws SAMLException             error processing artifact messages
     * @throws MessageEncodingException  error sending artifactRequest
     * @throws MessageDecodingException  error retrieving artifactResponse
     * @throws MetadataProviderException error resolving metadata
     * @throws SecurityException
     *                                   invalid message signature
     */
    protected void getArtifactResponse(String endpointURI, SAMLMessageContext context) throws SAMLException, MessageEncodingException, MessageDecodingException, MetadataProviderException, SecurityException {

        HttpPost postMethod = null;

        try {

            URI uri = new URI(context.getPeerEntityEndpoint().getLocation());
            postMethod = new HttpPost(uri);
            postMethod.setConfig(getHostConfiguration(uri, context));

            HttpClientOutTransport clientOutTransport = new HttpClientOutTransport(postMethod);
            HttpClientInTransport clientInTransport = new HttpClientInTransport(postMethod, endpointURI);

            context.setInboundMessageTransport(clientInTransport);
            context.setOutboundMessageTransport(clientOutTransport);

            // Send artifact retrieve message
            boolean signMessage = context.getPeerExtendedMetadata().isRequireArtifactResolveSigned();
            processor.sendMessage(context, signMessage, SAMLConstants.SAML2_SOAP11_BINDING_URI);

            log.debug("Sending ArtifactResolution message to {}", uri);
            int responseCode = httpClient.executeMethod(hc, postMethod);
            if (responseCode != 200) {
                String responseBody = postMethod.getResponseBodyAsString();
                throw new MessageDecodingException("Problem communicating with Artifact Resolution service, received response " + responseCode + ", body " + responseBody);
            }

            // Decode artifact response message.
            processor.retrieveMessage(context, SAMLConstants.SAML2_SOAP11_BINDING_URI);

        } catch (IOException | URISyntaxException e) {

            throw new MessageDecodingException("Error when sending request to artifact resolution service.", e);

        } finally {

            if (postMethod != null) {
                postMethod.releaseConnection();
            }

        }

    }

    /**
     * Method is expected to determine hostConfiguration used to send request to the server by back-channel. Configuration
     * should contain URI of the host and used protocol including all security settings.
     * <p>
     * Default implementation uses either default http protocol for non-SSL requests or constructs a separate
     * TrustManager using trust engine specified in the SAMLMessageContext - based either on MetaIOP (certificates
     * obtained from Metadata and ExtendedMetadata are trusted) or PKIX (certificates from metadata and ExtendedMetadata
     * including specified trust anchors are trusted and verified using PKIX).
     * <p>
     * Used trust engine can be customized as part of the SAMLContextProvider used to process this request.
     * <p>
     * Default values for the HostConfiguration are cloned from the HTTPClient set in this instance, when there are
     * no defaults available a new object is created.
     *
     * @param uri uri the request should be sent to
     * @param context context including the peer address
     * @return host configuration
     * @throws MessageEncodingException in case peer URI can't be parsed
     */
    protected RequestConfig getHostConfiguration(URI uri, SAMLMessageContext context) throws MessageEncodingException {

        try {


            RequestConfig.Builder builder = RequestConfig.custom();
            builder.setConnectTimeout(5000);

            if (uri.getScheme().equalsIgnoreCase("http")) {

                log.debug("Using HTTP configuration");

            } else {

                log.debug("Using HTTPS configuration");

                CriteriaSet criteriaSet = new CriteriaSet();
                criteriaSet.add(new EntityIdCriterion(context.getPeerEntityId()));
                criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
                criteriaSet.add(new UsageCriteria(UsageType.UNSPECIFIED));

                X509TrustManager trustManager = new X509TrustManager(criteriaSet, context.getLocalSSLTrustEngine());
                X509KeyManager manager = new X509KeyManager(context.getLocalSSLCredential());
                HostnameVerifier hostnameVerifier = context.getLocalSSLHostnameVerifier();

                LayeredConnectionSocketFactory socketFactory = getSSLSocketFactory(context, manager, trustManager, hostnameVerifier);



            }

            return builder.build();

        } catch (NoSuchAlgorithmException e) {
            throw new MessageEncodingException("Error getting SSL context, algorithm not found", e);
        } catch (KeyManagementException e) {
            throw new MessageEncodingException("Error getting SSL context, key issues", e);
        }

    }

    /**
     * Method returns SecureProtocolSocketFactory used to connect to create SSL connections for artifact resolution.
     * By default we create instance of org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory.
     *
     * @param context current SAML context
     * @param manager keys used for client authentication
     * @param trustManager trust manager for server verification
     * @param hostnameVerifier verifier for server hostname, or null
     * @return socket factory
     */
    protected LayeredConnectionSocketFactory getSSLSocketFactory(SAMLMessageContext context, X509KeyManager manager, X509TrustManager trustManager, HostnameVerifier hostnameVerifier)
        throws NoSuchAlgorithmException, KeyManagementException {
        if (isHostnameVerificationSupported()) {
            return new TLSProtocolSocketFactory(manager, trustManager, hostnameVerifier);
        } else {
            return new TLSProtocolSocketFactory(manager, trustManager);
        }
    }

    /**
     * Check for the latest OpenSAML library. Support for HostnameVerification was added in openws-1.5.1 and
     * customers might use previous versions of OpenSAML.
     *
     * @return true when OpenSAML library support hostname verification
     */
    protected boolean isHostnameVerificationSupported() {
        try {
            TLSProtocolSocketFactory.class.getConstructor(javax.net.ssl.X509KeyManager.class, javax.net.ssl.X509TrustManager.class, javax.net.ssl.HostnameVerifier.class);
            return true;
        } catch (NoSuchMethodException e) {
            log.warn("HostnameVerification is not supported, update your OpenSAML libraries");
            return false;
        }
    }

}
