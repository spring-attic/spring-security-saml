/*
 * Copyright 2009 Vladimir Schaefer
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
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.util.Assert;

import java.util.Date;
import java.util.Random;

/**
 * Base superclass for classes implementing processing of SAML messages.
 *
 * @author Vladimir Schaefer
 */
public abstract class AbstractProfileBase implements InitializingBean {

    /**
     * Maximum time from response creation when the message is deemed valid.
     */
    private int responseSkew = 60;

    /**
     * Maximum time between assertion creation and current time when the assertion is usable
     */
    private int maxAssertionTime = 3000;

    /**
     * Class logger.
     */
    protected final static Logger log = LoggerFactory.getLogger(WebSSOProfileImpl.class);

    protected MetadataManager metadata;
    protected SAMLProcessor processor;
    protected SAMLArtifactMap artifactMap;
    protected XMLObjectBuilderFactory builderFactory;

    public AbstractProfileBase() {
        this.builderFactory = Configuration.getBuilderFactory();
    }

    public AbstractProfileBase(SAMLProcessor processor, MetadataManager manager) {
        this();
        this.processor = processor;
        this.metadata = manager;
    }

    /**
     * Sets maximum difference between local time and time of the assertion creation which still allows
     * message to be processed. Basically determines maximum difference between clocks of the IDP and SP machines.
     * Defaults to 60.
     *
     * @param responseSkew response skew time (in seconds)
     */
    public void setResponseSkew(int responseSkew) {
        this.responseSkew = responseSkew;
    }

    /**
     * @return response skew time (in seconds)
     */
    public int getResponseSkew() {
        return responseSkew;
    }

    /**
     * Maximum time between assertion creation and current time when the assertion is usable
     * @return max assertion time
     */
    public int getMaxAssertionTime() {
        return maxAssertionTime;
    }

    /**
     * Customizes max assertion time between assertion creation and it's usability. Default to 3000 seconds.
     *
     * @param maxAssertionTime time in seconds
     */
    public void setMaxAssertionTime(int maxAssertionTime) {
        this.maxAssertionTime = maxAssertionTime;
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
        SPSSODescriptor spDescriptor = (SPSSODescriptor) metadata.getRole(spId, SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        if (spDescriptor == null) {
            throw new MetadataProviderException("There was no SP metadata with ID " + spId + " found, please check metadata bean in your Spring configuration");
        }
        return spDescriptor;
    }

    /**
     * Method calls the processor and sends the message contained in the context. Subclasses can provide additional
     * processing before the message delivery. Message is sent using binding defined in the peer entity of the context.
     *
     * @param context context
     * @param sign whether the message should be signed
     * @throws MetadataProviderException metadata error
     * @throws SAMLException SAML encoding error
     * @throws org.opensaml.ws.message.encoder.MessageEncodingException message encoding error
     */
    protected void sendMessage(SAMLMessageContext context, boolean sign) throws MetadataProviderException, SAMLException, MessageEncodingException {
        processor.sendMessage(context, sign);
    }

    /**
     * Method calls the processor and sends the message contained in the context. Subclasses can provide additional
     * processing before the message delivery. Message is sent using the specified binding.
     *
     * @param context context
     * @param sign whether the message should be signed
     * @param binding binding to use to send the message
     * @throws MetadataProviderException metadata error
     * @throws SAMLException SAML encoding error
     * @throws org.opensaml.ws.message.encoder.MessageEncodingException message encoding error
     */
    protected void sendMessage(SAMLMessageContext context, boolean sign, String binding) throws MetadataProviderException, SAMLException, MessageEncodingException {
        processor.sendMessage(context, sign, binding);
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
     * @param localEntityId entityId of the local party acting as message issuer
     * @param request request to be filled
     * @param service service to use as destination for the request
     */
    protected void buildCommonAttributes(String localEntityId, RequestAbstractType request, Endpoint service) {

        request.setID(generateID());
        request.setIssuer(getIssuer(localEntityId));
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(new DateTime());

        if (service != null) {
            // Service is now known when we do not know which IDP will be used
            request.setDestination(service.getLocation());
        }

    }

    protected Issuer getIssuer(String localEntityId) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(localEntityId);
        return issuer;
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

    protected void verifyIssuer(Issuer issuer, SAMLMessageContext context) throws SAMLException {
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

    protected void verifySignature(Signature signature, String IDPEntityID, SignatureTrustEngine trustEngine) throws org.opensaml.xml.security.SecurityException, ValidationException {

        if (trustEngine == null) {
            throw new SecurityException("Trust engine is not set, signature can't be verified");
        }

        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        validator.validate(signature);
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(IDPEntityID));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        log.debug("Verifying signature", signature);

        if (!trustEngine.validate(signature, criteriaSet)) {
            throw new ValidationException("Signature is not trusted or invalid");
        }

    }

    protected boolean isDateTimeSkewValid(int skewInSec, DateTime time) {
        long current = new Date().getTime();
        return time.isAfter(current - skewInSec * 1000) && time.isBefore(current + skewInSec * 1000);
    }

    @Autowired
    public void setMetadata(MetadataManager metadata) {
        this.metadata = metadata;
    }

    @Autowired(required = false)
    public void setProcessor(SAMLProcessor processor) {
        this.processor = processor;
    }

    // TODO autowire when ready
    public void setArtifactMap(SAMLArtifactMap artifactMap) {
        this.artifactMap = artifactMap;
    }

    public void afterPropertiesSet() throws Exception {
        // TODO verify artifact map when ready
        Assert.notNull(metadata, "Metadata must be set");
        Assert.notNull(processor, "SAML Processor must be set");
    }

}
