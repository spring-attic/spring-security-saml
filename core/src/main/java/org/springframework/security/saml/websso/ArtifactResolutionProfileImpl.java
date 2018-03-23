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

import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Set;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
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
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;

/**
 * Implementation of the artifact resolution protocol which uses Apache HTTPClient for SOAP binding transport.
 */
public class ArtifactResolutionProfileImpl extends ArtifactResolutionProfileBase {

    private String sslHostnameVerification = "default";

    /**
     * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is null
     * all keys in the keyStore will be treated as trusted.
     */
    private Set<String> trustedKeys;


    /**
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


            // Send artifact retrieve message
            boolean signMessage = context.getPeerExtendedMetadata().isRequireArtifactResolveSigned();
            processor.sendMessage(context, signMessage, SAMLConstants.SAML2_SOAP11_BINDING_URI);

            log.debug("Sending ArtifactResolution message to {}", uri);

            CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(RequestConfig.DEFAULT)
                .setDefaultHeaders(new ArrayList<>())
                .setDefaultCookieStore(new BasicCookieStore())
                .setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE)
                .build();

            CloseableHttpResponse response = client.execute(postMethod);

            int responseCode = response.getStatusLine().getStatusCode();
            if (responseCode != 200) {
                String responseBody = EntityUtils.toString(response.getEntity());
                throw new MessageDecodingException("Problem communicating with Artifact Resolution service, received response " + responseCode + ", body " + responseBody);
            }

            HttpClientOutTransport clientOutTransport = new HttpClientOutTransport(postMethod);
            HttpClientInTransport clientInTransport = new HttpClientInTransport(response, endpointURI);

            context.setInboundMessageTransport(clientInTransport);
            context.setOutboundMessageTransport(clientOutTransport);


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


            }

            return builder.build();

        } catch (Exception x) {
            if (x instanceof RuntimeException) {
                throw (RuntimeException)x;
            } else {
                throw new RuntimeException(x);
            }
        }

    }

    /**
     * Method returns SecureProtocolSocketFactory used to connect to create SSL connections for artifact resolution.
     * By default we create instance of org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory.
     *
     * @param context current SAML context
     * @param manager keys used for client authentication
     * @param trustManager trust manager for server verification
     * @return socket factory
     */
    protected LayeredConnectionSocketFactory getSSLSocketFactory(SAMLMessageContext context,
                                                                 org.springframework.security.saml.key.KeyManager manager,
                                                                 TrustManager trustManager)
        throws NoSuchAlgorithmException, KeyManagementException {
        if (isHostnameVerificationSupported()) {
            return new TLSProtocolSocketFactory(manager,
                                                trustManager,
                                                getTrustedKeys(),
                                                getSslHostnameVerification()
            );
        } else {
            return new TLSProtocolSocketFactory(manager,
                                                trustManager,
                                                getTrustedKeys(),
                                                "default");
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
            TLSProtocolSocketFactory.class.getConstructor(KeyManager.class,
                                                          TrustManager.class,
                                                          Set.class,
                                                          String.class);
            return true;
        } catch (NoSuchMethodException e) {
            log.warn("HostnameVerification is not supported, update your OpenSAML libraries");
            return false;
        }
    }

    public String getSslHostnameVerification() {
        return sslHostnameVerification;
    }

    public void setSslHostnameVerification(String sslHostnameVerification) {
        this.sslHostnameVerification = sslHostnameVerification;
    }

    public Set<String> getTrustedKeys() {
        return trustedKeys;
    }

    public void setTrustedKeys(Set<String> trustedKeys) {
        this.trustedKeys = trustedKeys;
    }
}
