/* Copyright 2009 Vladimir Schäfer
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
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.util.SAMLUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Random;

/**
 * Class implements WebSSO profile and offers capabilities for SP initialized SSO and
 * process Response coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect
 * bindings are supported.
 *
 * @author Vladimir Schäfer
 */
public class WebSSOProfileImpl implements WebSSOProfile {

    /**
     * Class logger.
     */
    private final static Logger log = LoggerFactory.getLogger(WebSSOProfileImpl.class);

    private MetadataManager metadata;
    private KeyStoreCredentialResolver keyManager;
    private XMLObjectBuilderFactory builderFactory;
    private String signingKey;
    private VelocityEngine velocityEngine;

    private static final int DEFAULT_PROXY_COUNT = 2;

    /**
     * Initializes the profile.
     *
     * @param metadata   metadata manager to be used
     * @param keyManager key manager
     * @param signingKey alias of key used for signing of assertions by local entity
     * @throws SAMLException error initializing the profile
     */
    public WebSSOProfileImpl(MetadataManager metadata, KeyStoreCredentialResolver keyManager, String signingKey) throws SAMLException {
        this.metadata = metadata;
        this.builderFactory = Configuration.getBuilderFactory();
        this.keyManager = keyManager;
        this.signingKey = signingKey;
        try {
            velocityEngine = new VelocityEngine();
            velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
            velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
            velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
            velocityEngine.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
            velocityEngine.init();
        } catch (Exception e) {
            log.debug("Error initializing velicoity engige", e);
            throw new SAMLException("Error configuring velocity", e);
        }
    }

    /**
     * Initializes SSO by creating AuthnRequest assertion and sending it to the IDP using the default binding.
     * Default IDP is used to send the request.
     *
     * @param options values specified by caller to customize format of sent request
     * @param messageStorage object capable of storing and retreiving SAML messages
     * @param request  request
     * @param response response
     * @throws SAMLException             error initializing SSO
     * @throws MetadataProviderException error retreiving needed metadata
     * @throws MessageEncodingException  error forming SAML message
     */
    public AuthnRequest initializeSSO(WebSSOProfileOptions options, SAMLMessageStorage messageStorage, HttpServletRequest request, HttpServletResponse response) throws SAMLException, MetadataProviderException, MessageEncodingException {

        // Initialize IDP
        String idpId = options.getIdp();
        if (idpId == null) {
            idpId = metadata.getDefaultIDP();
        }
        if (!metadata.isIDPValid(idpId)) {
            log.debug("Given IDP name is not valid", idpId);
            throw new MetadataProviderException("IDP with name " + idpId + " wasn't found in the list of configured IDPs");
        }
        EntityDescriptor idpEntityDescriptor = metadata.getEntityDescriptor(idpId);
        IDPSSODescriptor idpssoDescriptor = (IDPSSODescriptor) metadata.getRole(idpId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        if (idpssoDescriptor == null) {
            throw new MetadataProviderException("Given IDP "+idpId+" doesn't contain any IDPSSODescriptor element");
        }

        // Initialize hosted SP
        String spId = metadata.getHostedSPName();
        if (spId == null) {
            throw new MetadataProviderException("No hosted SP metadata ID is configured, please verify that property hostedSPName in metadata bean of your Spring configuration is correcly set");
        }
        SPSSODescriptor spDescriptor = (SPSSODescriptor) metadata.getRole(metadata.getHostedSPName(), SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        if (spDescriptor == null) {
            throw new MetadataProviderException("There was no SP metadata with ID "+metadata.getHostedSPName()+" found, please check metadata bean in your Spring configuration");
        }

        // Find default binding in case none is specified
        String binding = options.getBinding();
        if (binding == null) {
            binding = SAMLUtil.getDefaultBinding(idpssoDescriptor);
        }

        MessageEncoder encoder = getEncoder(binding);

        AssertionConsumerService assertionConsubmerForBinding = SAMLUtil.getAssertionConsubmerForBinding(spDescriptor, binding);
        SingleSignOnService bindingService = SAMLUtil.getServiceForBinding(idpssoDescriptor, binding);
        AuthnRequest authRequest = getAuthnRequest(options, idpEntityDescriptor, assertionConsubmerForBinding, bindingService);

        // TODO optionally implement support for authncontext, conditions, nameIDpolicy, subject

        BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> samlContext = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
        samlContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response, false));
        samlContext.setOutboundSAMLMessage(authRequest);
        samlContext.setPeerEntityEndpoint(bindingService);

        if (idpssoDescriptor.getWantAuthnRequestsSigned()) {
            samlContext.setOutboundSAMLMessageSigningCredential(getSPSigningCredential());
        }

        encoder.encode(samlContext);
        messageStorage.storeMessage(authRequest.getID(), authRequest);
        return authRequest;
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

    /**
     * Returns Credential object used to sign the message issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @return credential
     */
    private Credential getSPSigningCredential() {
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
     * Returns AuthnRequest SAML message to be used to demand authentication from an IDP descibed using
     * idpEntityDescriptor, with an expected reponse to the assertionConsumber address.
     *
     * @param idpEntityDescriptor entity descriptor of IDP this request should be sent to
     * @param assertionConsumber  assertion consumer where the IDP should respond
     * @param bindingService      service used to deliver the request
     * @return authnRequest ready to be sent to IDP
     * @throws SAMLException             error creating the message
     * @throws MetadataProviderException error retreiving metadata
     */
    protected AuthnRequest getAuthnRequest(WebSSOProfileOptions options, EntityDescriptor idpEntityDescriptor, AssertionConsumerService assertionConsumber, SingleSignOnService bindingService) throws SAMLException, MetadataProviderException {

        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();

        request.setID(generateID());
        request.setIsPassive(options.getPassive());
        request.setForceAuthn(options.getForceAuthN());

        buildCommonAttributes(request, bindingService);
        buildIssuer(request);
        buildScoping(request, idpEntityDescriptor, bindingService, options.isAllowProxy());
        buildReturnAddress(request, assertionConsumber);

        return request;
    }

    /**
     * Generates random ID to be used as Request/Response ID.
     *
     * @return random ID
     */
    private String generateID() {
        Random r = new Random();
        return 'a' + Long.toString(Math.abs(r.nextLong()), 20) + Long.toString(Math.abs(r.nextLong()), 20);
    }

    /**
     * Fills the request with version, issueinstants and destination data.
     *
     * @param request request to be filled
     * @param service service to use as destination for the request
     */
    private void buildCommonAttributes(RequestAbstractType request, SingleSignOnService service) {
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(new DateTime());
        request.setDestination(service.getLocation());
    }

    /**
     * Fills the request with assertion consumer service url and protocol binding based on assertionConsumer
     * to be used to deliver response from the IDP.
     *
     * @param request request
     * @param service service to deliver response to
     * @throws MetadataProviderException error retreiving metadata information
     */
    private void buildReturnAddress(AuthnRequest request, AssertionConsumerService service) throws MetadataProviderException {
        request.setVersion(SAMLVersion.VERSION_20);
        request.setAssertionConsumerServiceURL(service.getLocation());
        request.setProtocolBinding(service.getBinding());
    }

    /**
     * Fills the request with issuer type, with data about our local entity.
     *
     * @param request request
     */
    private void buildIssuer(RequestAbstractType request) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(metadata.getHostedSPName());
        request.setIssuer(issuer);
    }

    /**
     * Fills the request with information about scoping, including IDP in the scope IDP List.
     *
     * @param request             request to fill
     * @param idpEntityDescriptor idp descriptor
     * @param serviceURI          destination to send the request to
     * @param allowProxy          if true proxying will be allowed on the request
     */
    private void buildScoping(AuthnRequest request, EntityDescriptor idpEntityDescriptor, SingleSignOnService serviceURI, boolean allowProxy) {

        SAMLObjectBuilder<IDPEntry> idpEntryBuilder = (SAMLObjectBuilder<IDPEntry>) builderFactory.getBuilder(IDPEntry.DEFAULT_ELEMENT_NAME);
        IDPEntry idpEntry = idpEntryBuilder.buildObject();
        idpEntry.setProviderID(idpEntityDescriptor.getEntityID());
        idpEntry.setLoc(serviceURI.getLocation());

        SAMLObjectBuilder<IDPList> idpListBuilder = (SAMLObjectBuilder<IDPList>) builderFactory.getBuilder(IDPList.DEFAULT_ELEMENT_NAME);
        IDPList idpList = idpListBuilder.buildObject();
        idpList.getIDPEntrys().add(idpEntry);

        SAMLObjectBuilder<Scoping> scopingBuilder = (SAMLObjectBuilder<Scoping>) builderFactory.getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
        Scoping scoping = scopingBuilder.buildObject();
        scoping.setIDPList(idpList);

        if (allowProxy) {
            scoping.setProxyCount(new Integer(DEFAULT_PROXY_COUNT));
        }

        request.setScoping(scoping);
    }

}
