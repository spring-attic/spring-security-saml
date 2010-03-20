/*
 * Copyright 2009 Vladimir Schäfer
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

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.*;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SLF4JLogChute;

import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Random;

/**
 * Base superclass for classes implementing processing of SAML messages.
 *
 * @author Vladimir Schäfer
 */
public class AbstractProfileBase {

    /**
     * Maximum time from response creation when the message is deemed valid
     */
    protected static int DEFAULT_RESPONSE_SKEW = 60;

    /**
     * Maximum time between assertion creation and current time when the assertion is usable
     */
    protected static int MAX_ASSERTION_TIME = 3000;

    /**
     * Class logger.
     */
    protected final static Logger log = LoggerFactory.getLogger(WebSSOProfileImpl.class);
    protected MetadataManager metadata;
    protected CredentialResolver keyManager;
    protected XMLObjectBuilderFactory builderFactory;
    protected String signingKey;
    protected VelocityEngine velocityEngine;
    protected Decrypter decryper;

    /**
     * Trust engine used to verify SAML signatures
     */
    protected SignatureTrustEngine trustEngine;

    public AbstractProfileBase(MetadataManager metadata, String signingKey, CredentialResolver keyManager) {
        this.metadata = metadata;
        this.signingKey = signingKey;
        this.keyManager = keyManager;
        this.builderFactory = Configuration.getBuilderFactory();
        try {
            velocityEngine = new VelocityEngine();
            velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
            velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
            velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
            velocityEngine.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
            velocityEngine.setProperty(VelocityEngine.RUNTIME_LOG_LOGSYSTEM, new SLF4JLogChute());
            velocityEngine.init();
        } catch (Exception e) {
            log.debug("Error initializing velocity engine", e);
            throw new RuntimeException("Error configuring velocity", e);
        }

        // Decryption key
        KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(getSPSigningCredential());
        // Way to obtain encrypted key info from XML
        ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
        encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());
        // Entity used for decrypting of encrypted XML parts
        this.decryper = new Decrypter(null, resolver, encryptedKeyResolver);
    }

    public AbstractProfileBase(MetadataManager metadata, String signingKey, CredentialResolver keyManager, SignatureTrustEngine trustEngine) {
        this(metadata, signingKey, keyManager);
        this.trustEngine = trustEngine;
    }

    protected MessageEncoder getEncoder(String binding) throws SAMLException {
        if (binding.equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
            return new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
        } else if (binding.equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
            return new HTTPRedirectDeflateEncoder();
        } else {
            throw new SAMLException("Given binding is not supported");
        }
    }

    protected IDPSSODescriptor getIDPDescriptor(String idpId) throws MetadataProviderException {
        if (!metadata.isIDPValid(idpId)) {
            log.debug("IDP name of the authenticated user is not valid", idpId);
            throw new MetadataProviderException("IDP with name " + idpId + " wasn't found in the list of configured IDPs");
        }
        IDPSSODescriptor idpssoDescriptor = (IDPSSODescriptor) metadata.getRole(idpId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        if (idpssoDescriptor == null) {
            throw new MetadataProviderException("Given IDP " + idpId + " doesn't contain any IDPSSODescriptor element");
        }
        return idpssoDescriptor;
    }

    protected SPSSODescriptor getSPDescriptor(String spId) throws MetadataProviderException {
        if (spId == null) {
            throw new MetadataProviderException("No hosted SP metadata ID is configured, please verify that property hostedSPName in metadata bean of your Spring configuration is correctly set");
        }
        SPSSODescriptor spDescriptor = (SPSSODescriptor) metadata.getRole(metadata.getHostedSPName(), SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        if (spDescriptor == null) {
            throw new MetadataProviderException("There was no SP metadata with ID " + metadata.getHostedSPName() + " found, please check metadata bean in your Spring configuration");
        }
        return spDescriptor;
    }

    protected void sendMessage(SAMLMessageStorage messageStorage, boolean sign, RequestAbstractType message, Endpoint endpoint, HttpServletResponse response) throws SAMLException, MessageEncodingException {
        sendMessage(sign, message, endpoint, response);
        messageStorage.storeMessage(message.getID(), message);
    }

    protected void sendMessage(boolean sign, SignableSAMLObject message, Endpoint endpoint, HttpServletResponse response) throws SAMLException, MessageEncodingException {
        BasicSAMLMessageContext<SAMLObject, SignableSAMLObject, SAMLObject> samlContext = new BasicSAMLMessageContext<SAMLObject, SignableSAMLObject, SAMLObject>();
        samlContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response, false));
        samlContext.setOutboundMessage(message);
        samlContext.setOutboundSAMLMessage(message);
        samlContext.setPeerEntityEndpoint(endpoint);

        if (sign) {
            samlContext.setOutboundSAMLMessageSigningCredential(getSPSigningCredential());
        }

        MessageEncoder encoder = getEncoder(endpoint.getBinding());
        encoder.encode(samlContext);
    }

    protected Status getStatus(String code, String statusMessage) {
        SAMLObjectBuilder<StatusCode> codeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = codeBuilder.buildObject();
        statusCode.setValue(code);

        SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);

        if (statusMessage != null) {
            SAMLObjectBuilder<StatusMessage> messageBuilder = (SAMLObjectBuilder<StatusMessage>) builderFactory.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
            StatusMessage statusMessageObject = messageBuilder.buildObject();
            statusMessageObject.setMessage(statusMessage);
            status.setStatusMessage(statusMessageObject);
        }

        return status;
    }

    /**
     * Fills the request with version, issue instants and destination data.
     *
     * @param request request to be filled
     * @param service service to use as destination for the request
     */
    protected void buildCommonAttributes(RequestAbstractType request, Endpoint service) {
        request.setID(generateID());
        request.setIssuer(getIssuer());
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(new DateTime());
        request.setDestination(service.getLocation());
    }

    protected Issuer getIssuer() {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(metadata.getHostedSPName());
        return issuer;
    }

    /**
     * Returns Credential object used to sign the message issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @return credential
     */
    protected Credential getSPSigningCredential() {
        try {
            CriteriaSet cs = new CriteriaSet();
            EntityIDCriteria criteria = new EntityIDCriteria(signingKey);
            cs.add(criteria);
            return keyManager.resolveSingle(cs);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new SAMLRuntimeException("Can't obtain SP signing key", e);
        }
    }

    /**
     * Generates random ID to be used as Request/Response ID.
     *
     * @return random ID
     */
    protected String generateID() {
        Random r = new Random();
        return 'a' + Long.toString(Math.abs(r.nextLong()), 20) + Long.toString(Math.abs(r.nextLong()), 20);
    }

    protected void verifyIssuer(Issuer issuer, BasicSAMLMessageContext context) throws SAMLException {
        // Validate format of issuer
        if (issuer.getFormat() != null && !issuer.getFormat().equals(NameIDType.ENTITY)) {
            log.debug("Assertion invalidated by issuer type", issuer.getFormat());
            throw new SAMLException("SAML Assertion is invalid");
        }

        // Validate that issuer is expected peer entity
        if (!context.getPeerEntityMetadata().getEntityID().equals(issuer.getValue())) {
            log.debug("Assertion invalidated by unexpected issuer value", issuer.getValue());
            throw new SAMLException("SAML Assertion is invalid");
        }
    }

    protected void verifySignature(Signature signature, String IDPEntityID) throws org.opensaml.xml.security.SecurityException, ValidationException {
        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        validator.validate(signature);
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(IDPEntityID));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        log.debug("Verifying signature", signature);
        trustEngine.validate(signature, criteriaSet);
    }

    protected boolean isDateTimeSkewValid(int skewInSec, DateTime time) {
        long current = new Date().getTime();
        int futureSkew = 3;
        return time.isAfter(current - skewInSec * 1000) && time.isBefore(current + futureSkew * 1000);
    }
}
