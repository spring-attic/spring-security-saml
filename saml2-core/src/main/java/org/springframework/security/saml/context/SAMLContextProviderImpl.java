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

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.security.ServletRequestX509CredentialAdapter;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.trust.ExplicitX509CertificateTrustEngine;
import org.opensaml.xml.security.trust.TrustEngine;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.PKIXX509CredentialTrustEngine;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.signature.impl.PKIXSignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.trust.MetadataCredentialResolver;
import org.springframework.security.saml.trust.PKIXInformationResolver;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Class is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP) is responsible
 * for it's handling.
 *
 * @author Vladimir Schaefer
 */
public class SAMLContextProviderImpl implements SAMLContextProvider, InitializingBean {

    protected final static Logger logger = LoggerFactory.getLogger(SAMLContextProviderImpl.class);

    // Way to obtain encrypted key info from XML Encryption
    private static ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();

    static {
        encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());
    }

    protected KeyManager keyManager;
    protected MetadataManager metadata;
    protected MetadataCredentialResolver metadataResolver;
    protected PKIXInformationResolver pkixResolver;

    /**
     * Creates a SAMLContext with local entity values filled. Also request and response must be stored in the context
     * as message transports.
     *
     * @param request  request
     * @param response response
     * @return context
     * @throws MetadataProviderException in case of metadata problems
     */
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {

        SAMLMessageContext context = new SAMLMessageContext();
        populateGenericContext(request, response, context);
        populateLocalEntityId(context, request.getContextPath());
        populateLocalContext(context);
        return context;

    }

    /**
     * Creates a SAMLContext with local entity and peer values filled. Also request and response must be stored in the context
     * as message transports. Should be used when both local entity and peer entity can be determined from the request.
     *
     * @param request request
     * @param response response
     * @return context
     * @throws MetadataProviderException in case of metadata problems
     */
    public SAMLMessageContext getLocalAndPeerEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {

        SAMLMessageContext context = new SAMLMessageContext();
        populateGenericContext(request, response, context);
        populateLocalEntityId(context, request.getContextPath());
        populateLocalContext(context);
        populatePeerEntityId(context);
        populatePeerContext(context);
        return context;

    }

    /**
     * Creates a SAMLContext with local entity values filled. Also request and response must be stored in the context
     * as message transports. Local entity is populated based on the SAMLCredential.
     *
     * @param request    request
     * @param response   response
     * @param credential credential to load entity for
     * @return context
     * @throws MetadataProviderException in case of metadata problems
     */
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response, SAMLCredential credential) throws MetadataProviderException {

        SAMLMessageContext context = new SAMLMessageContext();
        populateLocalEntityId(context, credential);
        populateGenericContext(request, response, context);
        populateLocalContext(context);
        return context;

    }

    /**
     * Loads the IDP_PARAMETER from the request and if it is not null verifies whether IDP with this value is valid
     * IDP in our circle of trust. Processing fails when IDP is not valid. IDP is set as PeerEntityId in the context.
     * <p/>
     * If request parameter is null the default IDP is returned.
     *
     * @param context context to populate ID for
     * @throws MetadataProviderException in case provided IDP value is invalid
     */
    protected void populatePeerEntityId(SAMLMessageContext context) throws MetadataProviderException {

        String idp = ((HTTPInTransport) context.getInboundMessageTransport()).getParameterValue(SAMLEntryPoint.IDP_PARAMETER);
        if (idp != null) {
            if (!metadata.isIDPValid(idp)) {
                logger.debug("User specified IDP {} is invalid", idp);
                throw new MetadataProviderException("Specified IDP is not valid: " + idp);
            } else {
                logger.debug("Using user specified IDP {}", idp);
                context.setPeerUserSelected(true);
            }
        } else {
            idp = metadata.getDefaultIDP();
            logger.debug("No IDP specified, using default {}", idp);
            context.setPeerUserSelected(false);
        }

        context.setPeerEntityId(idp);
        context.setPeerEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

    }

    /**
     * Populates additional information about the peer based on the previously loaded peerEntityId.
     *
     * @param samlContext to populate
     * @throws MetadataProviderException in case metadata problem is encountered
     */
    private void populatePeerContext(SAMLMessageContext samlContext) throws MetadataProviderException {

        String peerEntityId = samlContext.getPeerEntityId();
        QName peerEntityRole = samlContext.getPeerEntityRole();

        if (peerEntityId == null) {
            throw new MetadataProviderException("Peer entity ID wasn't specified, but is requested");
        }

        EntityDescriptor entityDescriptor = metadata.getEntityDescriptor(peerEntityId);
        RoleDescriptor roleDescriptor = metadata.getRole(peerEntityId, peerEntityRole, SAMLConstants.SAML20P_NS);
        ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(peerEntityId);

        if (entityDescriptor == null || roleDescriptor == null) {
            throw new MetadataProviderException("Metadata for entity " + peerEntityId + " and role " + peerEntityRole + " wasn't found");
        }

        samlContext.setPeerEntityMetadata(entityDescriptor);
        samlContext.setPeerEntityRoleMetadata(roleDescriptor);
        samlContext.setPeerExtendedMetadata(extendedMetadata);


    }

    private void populateGenericContext(HttpServletRequest request, HttpServletResponse response, SAMLMessageContext context) throws MetadataProviderException {

        HttpServletRequestAdapter inTransport = new HttpServletRequestAdapter(request);
        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

        context.setMetadataProvider(metadata);
        context.setInboundMessageTransport(inTransport);
        context.setOutboundMessageTransport(outTransport);

    }

    private void populateLocalContext(SAMLMessageContext context) throws MetadataProviderException {

        populateLocalEntity(context);
        populateDecrypter(context);
        populateSSLCredential(context);
        populatePeerSSLCredential(context);
        populateTrustEngine(context);
        populateSSLTrustEngine(context);

    }

    /**
     * Populates localEntityId and localEntityRole based on the SAMLCredential.
     *
     * @param context    context to populate
     * @param credential credential
     * @throws MetadataProviderException in case entity id can' be populated
     */
    protected void populateLocalEntityId(SAMLMessageContext context, SAMLCredential credential) throws MetadataProviderException {

        String entityID = credential.getLocalEntityID();
        context.setLocalEntityId(entityID);
        context.setLocalEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

    }

    /**
     * Method tries to load localEntityAlias and localEntityRole from the request path. Path is supposed to be in format:
     * https(s)://server:port/application/saml/filterName/alias/aliasName/idp|sp?query. In case alias is missing from
     * the path defaults are used. Otherwise localEntityId and sp or idp localEntityRole is entered into the context.
     * <p/>
     * In case alias entity id isn't found an exception is raised.
     *
     * @param context     context to populate fields localEntityId and localEntityRole for
     * @param contextPath context path to parse entityId and entityRole from
     * @throws MetadataProviderException in case entityId can't be populated
     */
    protected void populateLocalEntityId(SAMLMessageContext context, String contextPath) throws MetadataProviderException {

        if (contextPath == null) {
            contextPath = "";
        }

        int filterIndex = contextPath.indexOf("/alias/");
        if (filterIndex != -1) { // Alias entityId

            String localAlias = contextPath.substring(filterIndex + 7);
            QName localEntityRole;

            int entityTypePosition = localAlias.lastIndexOf('/');
            if (entityTypePosition != -1) {
                String entityRole = localAlias.substring(entityTypePosition + 1);
                if ("idp".equalsIgnoreCase(entityRole)) {
                    localEntityRole = IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
                } else {
                    localEntityRole = SPSSODescriptor.DEFAULT_ELEMENT_NAME;
                }
                localAlias = localAlias.substring(0, entityTypePosition);
            } else {
                localEntityRole = SPSSODescriptor.DEFAULT_ELEMENT_NAME;
            }


            // Populate entityId
            String localEntityId = metadata.getEntityIdForAlias(localAlias);

            if (localEntityId == null) {
                throw new MetadataProviderException("No local entity found for alias " + localAlias + ", verify your configuration.");
            }

            context.setLocalEntityId(localEntityId);
            context.setLocalEntityRole(localEntityRole);

        } else { // Defaults

            context.setLocalEntityId(metadata.getHostedSPName());
            context.setLocalEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);

        }

    }

    /**
     * Method populates fields localEntityId, localEntityRole, localEntityMetadata, localEntityRoleMetadata and peerEntityRole.
     * In case fields localAlias, localEntityId, localEntiyRole or peerEntityRole are set they are used, defaults of default SP and IDP as a peer
     * are used instead.
     *
     * @param samlContext context to populate
     * @throws org.opensaml.saml2.metadata.provider.MetadataProviderException
     *          in case metadata do not contain expected entities or localAlias is specified but not found
     */
    private void populateLocalEntity(SAMLMessageContext samlContext) throws MetadataProviderException {

        String localEntityId = samlContext.getLocalEntityId();
        QName localEntityRole = samlContext.getLocalEntityRole();

        if (localEntityId == null) {
            throw new MetadataProviderException("No hosted service provider is configured and no alias was selected");
        }

        EntityDescriptor entityDescriptor = metadata.getEntityDescriptor(localEntityId);
        RoleDescriptor roleDescriptor = metadata.getRole(localEntityId, localEntityRole, SAMLConstants.SAML20P_NS);
        ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(localEntityId);

        if (entityDescriptor == null || roleDescriptor == null) {
            throw new MetadataProviderException("Metadata for entity " + localEntityId + " and role " + localEntityRole + " wasn't found");
        }

        samlContext.setLocalEntityMetadata(entityDescriptor);
        samlContext.setLocalEntityRoleMetadata(roleDescriptor);
        samlContext.setLocalExtendedMetadata(extendedMetadata);

        if (extendedMetadata.getSigningKey() != null) {
            samlContext.setLocalSigningCredential(keyManager.getCredential(extendedMetadata.getSigningKey()));
        } else {
            samlContext.setLocalSigningCredential(keyManager.getDefaultCredential());
        }

    }

    /**
     * Populates X509 Credential used to authenticate this machine against peer servers. Uses key with alias specified
     * in extended metadata under TlsKey, when not set uses the default credential.
     *
     * @param samlContext context to populate
     */
    protected void populateSSLCredential(SAMLMessageContext samlContext) {

        X509Credential tlsCredential;
        if (samlContext.getLocalExtendedMetadata().getTlsKey() != null) {
            tlsCredential = (X509Credential) keyManager.getCredential(samlContext.getLocalExtendedMetadata().getTlsKey());
        } else {
            tlsCredential = (X509Credential) keyManager.getDefaultCredential();
        }

        samlContext.setLocalSSLCredential(tlsCredential);

    }

    /**
     * Tries to load peer SSL certificate from the inbound message transport using attribute
     * "javax.servlet.request.X509Certificate". If found sets peerSSLCredential in the context.
     *
     * @param samlContext context to populate
     */
    protected void populatePeerSSLCredential(SAMLMessageContext samlContext) {

        X509Certificate[] chain = (X509Certificate[]) samlContext.getInboundMessageTransport().getAttribute(ServletRequestX509CredentialAdapter.X509_CERT_REQUEST_ATTRIBUTE);

        if (chain != null && chain.length > 0) {

            logger.debug("Found certificate chain from request {}", chain[0]);
            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(chain[0]);
            credential.setEntityCertificateChain(Arrays.asList(chain));
            samlContext.setPeerSSLCredential(credential);

        }

    }

    /**
     * Populates a decrypter based on settings in the extended metadata or using a default credential when no
     * encryption credential is specified in the extended metadata.
     *
     * @param samlContext context to populate decryptor for.
     */
    protected void populateDecrypter(SAMLMessageContext samlContext) {

        // Locate encryption key for this entity
        Credential encryptionCredential;
        if (samlContext.getLocalExtendedMetadata().getEncryptionKey() != null) {
            encryptionCredential = keyManager.getCredential(samlContext.getLocalExtendedMetadata().getEncryptionKey());
        } else {
            encryptionCredential = keyManager.getDefaultCredential();
        }

        // Entity used for decrypting of encrypted XML parts
        // Extracts EncryptedKey from the encrypted XML using the encryptedKeyResolver and attempts to decrypt it
        // using private keys supplied by the resolver.
        KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(encryptionCredential);

        Decrypter decrypter = new Decrypter(null, resolver, encryptedKeyResolver);
        decrypter.setRootInNewDocument(true);

        samlContext.setLocalDecrypter(decrypter);

    }

    /**
     * Based on the settings in the extended metadata either creates a PKIX trust engine with trusted keys specified
     * in the extended metadata as anchors or (by default) an explicit trust engine using data from the metadata or
     * from the values overriden in the ExtendedMetadata.
     *
     * @param samlContext context to populate
     */
    protected void populateTrustEngine(SAMLMessageContext samlContext) {
        SignatureTrustEngine engine;
        if ("pkix".equalsIgnoreCase(samlContext.getLocalExtendedMetadata().getSecurityProfile())) {
            engine = new PKIXSignatureTrustEngine(pkixResolver, Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());
        } else {
            engine = new ExplicitKeySignatureTrustEngine(metadataResolver, Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());
        }
        samlContext.setLocalTrustEngine(engine);
    }

    /**
     * Based on the settings in the extended metadata either creates a PKIX trust engine with trusted keys specified
     * in the extended metadata as anchors or (by default) an explicit trust engine using data from the metadata or
     * from the values overriden in the ExtendedMetadata. The trust engine is used to verify SSL connections.
     *
     * @param samlContext context to populate
     */
    protected void populateSSLTrustEngine(SAMLMessageContext samlContext) {
        TrustEngine<X509Credential> engine;
        if ("pkix".equalsIgnoreCase(samlContext.getLocalExtendedMetadata().getSecurityProfile())) {
            engine = new PKIXX509CredentialTrustEngine(pkixResolver);
        } else {
            engine = new ExplicitX509CertificateTrustEngine(metadataResolver);
        }
        samlContext.setLocalSSLTrustEngine(engine);
    }

    @Autowired
    public void setMetadata(MetadataManager metadata) {
        this.metadata = metadata;
    }

    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * Verifies that required entities were autowired or set and initializes resolvers used to construct trust engines.
     *
     * @throws javax.servlet.ServletException
     */
    public void afterPropertiesSet() throws ServletException {

        Assert.notNull(keyManager, "Key manager must be set");
        Assert.notNull(metadata, "Metadata must be set");

        metadataResolver = new MetadataCredentialResolver(metadata, keyManager);
        metadataResolver.setMeetAllCriteria(false);
        metadataResolver.setUnevaluableSatisfies(true);
        pkixResolver = new PKIXInformationResolver(metadataResolver, metadata, keyManager);

    }

}