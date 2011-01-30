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
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

/**
 * Class is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP) is responsible
 * for it's handling.
 *
 * @author Vladimir Schaefer
 */
public class SAMLContextProviderImpl implements SAMLContextProvider {

    // Way to obtain encrypted key info from XML Encryption
    private static ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();

    static {
        encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());
    }

    protected KeyManager keyManager;
    protected MetadataManager metadata;


    /**
     * Creates a SAMLContext with local entity values filled. Also request and response must be stored in the context
     * as message transports.
     *
     * @param request request
     * @param response response
     * @return context
     * @throws MetadataProviderException in case of metadata problems
     */
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {

        HttpServletRequestAdapter inTransport = new HttpServletRequestAdapter(request);
        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

        SAMLMessageContext context = new SAMLMessageContext();

        context.setMetadataProvider(metadata);
        context.setInboundMessageTransport(inTransport);
        context.setOutboundMessageTransport(outTransport);

        populateLocalAlias(context, request.getContextPath());
        populateLocalEntity(context);
        populateDecrypter(context);
        populateTrustEngine(context);

        return context;

    }

    /**
     * Method tries to load localEntityAlias and localEntityRole from the request path. Path is supposed to be in format:
     * https(s)://server:port/application/saml/filterName/alias/aliasName/idp|sp?query. In case alias is missing from
     * the path defaults are used. Otherwise entityId and sp or idp is entered into the context.
     * <p/>
     * Method doesn't verify whether entity with the found id exists in the metadata.
     *
     * @param context     context to populate fields localEntityId and localEntityRole for
     * @param contextPath context path to parse entityId and entityRole from
     */
    protected void populateLocalAlias(SAMLMessageContext context, String contextPath) {

        if (contextPath == null) {
            return; // TODO fail?
        }

        int filterIndex = contextPath.indexOf("/alias/");
        if (filterIndex != -1) {

            String localAlias = contextPath.substring(filterIndex + 7);
            QName localEntityRole = null;

            int entityTypePosition = localAlias.lastIndexOf('/');
            if (entityTypePosition != -1) {
                String entityRole = localAlias.substring(entityTypePosition + 1);
                if ("idp".equalsIgnoreCase(entityRole)) {
                    localEntityRole = IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
                } else {
                    localEntityRole = SPSSODescriptor.DEFAULT_ELEMENT_NAME;
                }
                localAlias = localAlias.substring(0, entityTypePosition);
            }

            context.setLocalAlias(localAlias);
            context.setLocalEntityRole(localEntityRole);

        }

    }

    /**
     * Method populates fields localEntityId, localEntityRole, localEntityMetadata, localEntityRoleMetadata and peerEntityRole.
     * In case fields localAlias, localEntityId, localEntiyRole or peerEntityRole are set they are used, defaults of default SP and IDP as a peer
     * are used instead.
     *
     * @param samlContext context to populate
     * @throws org.opensaml.saml2.metadata.provider.MetadataProviderException in case metadata do not contain expected entities or localAlias is specified but not found
     */
    protected void populateLocalEntity(SAMLMessageContext samlContext) throws MetadataProviderException {

        String localAlias = samlContext.getLocalAlias();
        String localEntityId = samlContext.getLocalEntityId();
        QName localEntityRole = samlContext.getLocalEntityRole();

        // Load entity by alias
        if (localAlias != null) {
            localEntityId = metadata.getEntityIdForAlias(localAlias);
            if (localEntityId == null) {
                throw new MetadataProviderException("No local entity found for alias " + localAlias + ", verify your configuration.");
            }
        }

        if (localEntityId == null) {
            localEntityId = metadata.getHostedSPName();
        }
        if (localEntityRole == null) {
            localEntityRole = SPSSODescriptor.DEFAULT_ELEMENT_NAME;
        }

        if (localEntityId == null) {
            throw new MetadataProviderException("No hosted service provider is configured");
        }

        EntityDescriptor entityDescriptor = metadata.getEntityDescriptor(localEntityId);
        RoleDescriptor roleDescriptor = metadata.getRole(localEntityId, localEntityRole, SAMLConstants.SAML20P_NS);
        ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(localEntityId);

        if (entityDescriptor == null || roleDescriptor == null) {
            throw new MetadataProviderException("Metadata for entity " + localEntityId + " and role " + localEntityRole + " weren't found");
        }

        samlContext.setLocalAlias(localAlias);
        samlContext.setLocalEntityId(localEntityId);
        samlContext.setLocalEntityRole(localEntityRole);
        samlContext.setLocalEntityMetadata(entityDescriptor);
        samlContext.setLocalEntityRoleMetadata(roleDescriptor);
        samlContext.setLocalExtendedMetadata(extendedMetadata);

        if (extendedMetadata.getSingingKey() != null) {
            samlContext.setLocalSigningCredential(keyManager.getCredential(extendedMetadata.getSingingKey()));
        } else {
            samlContext.setLocalSigningCredential(keyManager.getDefaultCredential());
        }

    }

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

    protected void populateTrustEngine(SAMLMessageContext samlContext) {

        MetadataCredentialResolver credentialResolver = new MetadataCredentialResolver(metadata);
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());
        samlContext.setLocalTrustEngine(trustEngine);

    }

    @Autowired
    public void setMetadata(MetadataManager metadata) {
        this.metadata = metadata;
    }

    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    // TODO verification of set entities

}