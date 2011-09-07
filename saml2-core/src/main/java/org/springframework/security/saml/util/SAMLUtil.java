/*
 * Copyright 2009-2010 Vladimir Schaefer
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
package org.springframework.security.saml.util;

import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.metadata.MetadataManager;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;

/**
 * Utility class for SAML entities
 *
 * @author Vladimir Schaefer
 */
public class SAMLUtil {

    private final static Logger logger = LoggerFactory.getLogger(SAMLUtil.class);

    /**
     * Method determines binding supported by the given endpoint. Usually the biding is encoded in the binding attribute
     * of the endpoint, but in some cases more processing is needed (e.g. for HoK profile).
     *
     * @param endpoint endpoint
     * @return binding supported by the endpoint
     * @throws MetadataProviderException in case binding can't be determined
     */
    public static String getBindingForEndpoint(Endpoint endpoint) {

        String bindingName = endpoint.getBinding();

        // For HoK profile the used binding is determined in a different way
        if (org.springframework.security.saml.SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI.equals(bindingName)) {
            QName attributeName = org.springframework.security.saml.SAMLConstants.WEBSSO_HOK_METADATA_ATT_NAME;
            String endpointLocation = endpoint.getUnknownAttributes().get(attributeName);
            if (endpointLocation != null) {
                bindingName = endpointLocation;
            } else {
                throw new SAMLRuntimeException("Holder of Key profile endpoint doesn't contain attribute hoksso:ProtocolBinding");
            }
        }

        return bindingName;

    }

    /**
     * Returns Single logout service for given binding of the IDP.
     *
     * @param descriptor IDP to search for service in
     * @param binding    binding supported by the service
     * @return SSO service capable of handling the given binding
     * @throws MetadataProviderException if the service can't be determined
     */
    public static SingleLogoutService getLogoutServiceForBinding(SSODescriptor descriptor, String binding) throws MetadataProviderException {
        List<SingleLogoutService> services = descriptor.getSingleLogoutServices();
        for (SingleLogoutService service : services) {
            if (binding.equals(service.getBinding())) {
                return service;
            }
        }
        logger.debug("No binding found for IDP with binding " + binding);
        throw new MetadataProviderException("Binding " + binding + " is not supported for this IDP");
    }

    public static String getLogoutBinding(IDPSSODescriptor idp, SPSSODescriptor sp) throws MetadataProviderException {

        List<SingleLogoutService> logoutServices = idp.getSingleLogoutServices();
        if (logoutServices.size() == 0) {
            throw new MetadataProviderException("IDP doesn't contain any SingleLogout endpoints");
        }

        String binding = null;

        // Let's find first binding supported by both IDP and SP
        idp:
        for (SingleLogoutService idpService : logoutServices) {
            for (SingleLogoutService spService : sp.getSingleLogoutServices()) {
                if (idpService.getBinding().equals(spService.getBinding())) {
                    binding = idpService.getBinding();
                    break idp;
                }
            }
        }

        // In case there's no common endpoint let's use first available
        if (binding == null) {
            binding = idp.getSingleLogoutServices().iterator().next().getBinding();
        }

        return binding;
    }

    /**
     * Returns default binding supported by IDP.
     *
     * @param descriptor descriptor to return binding for
     * @return first binding in the list of supported
     * @throws MetadataProviderException no binding found
     */
    public static String getDefaultBinding(IDPSSODescriptor descriptor) throws MetadataProviderException {
        for (SingleSignOnService service : descriptor.getSingleSignOnServices()) {
            return service.getBinding();
        }
        throw new MetadataProviderException("No SSO binding found for IDP");
    }

    public static IDPSSODescriptor getIDPSSODescriptor(EntityDescriptor idpEntityDescriptor) throws MessageDecodingException {

        IDPSSODescriptor idpSSODescriptor = idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        if (idpSSODescriptor == null) {
            logger.error("Could not find an IDPSSODescriptor in metadata.");
            throw new MessageDecodingException("Could not find an IDPSSODescriptor in metadata.");
        }

        return idpSSODescriptor;

    }

    /**
     * Loads the assertionConsumerIndex designated by the index. In case an index is specified the consumer
     * is located and returned, otherwise default consumer is used.
     *
     * @param ssoDescriptor descriptor
     * @param index         to load, can be null
     * @return consumer service
     * @throws org.opensaml.common.SAMLRuntimeException
     *          in case assertionConsumerService with given index isn't found
     */
    public static AssertionConsumerService getConsumerService(SPSSODescriptor ssoDescriptor, Integer index) {
        if (index != null) {
            for (AssertionConsumerService service : ssoDescriptor.getAssertionConsumerServices()) {
                if (index.equals(service.getIndex())) {
                    logger.debug("Found assertionConsumerService with index {} and binding {}", index, service.getBinding());
                    return service;
                }
            }
            throw new SAMLRuntimeException("AssertionConsumerService with index " + index + " wasn't found for ServiceProvider " + ssoDescriptor.getID() + ", please check your metadata");
        }
        logger.debug("Index for AssertionConsumerService not specified, returning default");
        return ssoDescriptor.getDefaultAssertionConsumerService();
    }

    public static ArtifactResolutionService getArtifactResolutionService(IDPSSODescriptor idpssoDescriptor, int endpointIndex) throws MessageDecodingException {

        List<ArtifactResolutionService> artifactResolutionServices = idpssoDescriptor.getArtifactResolutionServices();
        if (artifactResolutionServices == null || artifactResolutionServices.size() == 0) {
            logger.error("Could not find any artifact resolution services in metadata.");
            throw new MessageDecodingException("Could not find any artifact resolution services in metadata.");
        }

        ArtifactResolutionService artifactResolutionService = null;
        for (ArtifactResolutionService ars : artifactResolutionServices) {
            if (ars.getIndex() == endpointIndex) {
                artifactResolutionService = ars;
                break;
            }
        }

        if (artifactResolutionService == null) {
            throw new MessageDecodingException("Could not find artifact resolution service with index " + endpointIndex + " in IDP data.");
        }

        return artifactResolutionService;

    }

    /**
     * Determines whether filter with the given name should be invoked for the current request. Filter is used
     * when requestURI contains the filterName.
     *
     * @param filterName name of the filter to search URI for
     * @param request    request
     * @return true if filter should be processed for this request
     */
    public static boolean processFilter(String filterName, HttpServletRequest request) {
        return (request.getRequestURI().contains(filterName));
    }

    /**
     * Helper method compares whether SHA-1 hash of the entityId equals the hashID.
     *
     * @param hashID   hash id to compare
     * @param entityId entity id to hash and verify
     * @return true if values match
     * @throws MetadataProviderException in case SHA-1 hash can't be initialized
     */
    public static boolean compare(byte[] hashID, String entityId) throws MetadataProviderException {

        try {

            MessageDigest sha1Digester = MessageDigest.getInstance("SHA-1");
            byte[] hashedEntityId = sha1Digester.digest(entityId.getBytes());

            for (int i = 0; i < hashedEntityId.length; i++) {
                if (hashedEntityId[i] != hashID[i]) {
                    return false;
                }
            }

            return true;

        } catch (NoSuchAlgorithmException e) {
            throw new MetadataProviderException("SHA-1 message digest not available", e);
        }

    }

    /**
     * Verifies that the alias is valid.
     *
     * @param alias alias to verify
     * @throws MetadataProviderException in case any validation problem is found
     */
    public static void verifyAlias(String alias, String entityId) throws MetadataProviderException {

        if (alias == null) {
            throw new MetadataProviderException("Alias for entity " + entityId + " is null");
        } else if (alias.length() == 0) {
            throw new MetadataProviderException("Alias for entity " + entityId + " is empty");
        } else if (!alias.matches("\\p{ASCII}*")) {
            throw new MetadataProviderException("Only ASCII characters can be used in the alias " + alias + " for entity " + entityId);
        }

    }

    /**
     * Parses list of all Base64 encoded certificates found inside the KeyInfo element. All present X509Data
     * elements are processed.
     *
     * @param keyInfo key info to parse
     * @return found base64 encoded certificates
     */
    public static List<String> getBase64EncodeCertificates(KeyInfo keyInfo) {

        List<String> certList = new LinkedList<String>();

        if (keyInfo == null) {
            return certList;
        }

        List<X509Data> x509Datas = keyInfo.getX509Datas();
        for (X509Data x509Data : x509Datas) {
            if (x509Data != null) {
                certList.addAll(getBase64EncodedCertificates(x509Data));
            }
        }

        return certList;

    }

    /**
     * Parses list of Base64 encoded certificates present in the X509Data element.
     *
     * @param x509Data data to parse
     * @return list with 0..n certificates
     */
    public static List<String> getBase64EncodedCertificates(X509Data x509Data) {

        List<String> certList = new LinkedList<String>();

        if (x509Data == null) {
            return certList;
        }

        for (org.opensaml.xml.signature.X509Certificate xmlCert : x509Data.getX509Certificates()) {
            if (xmlCert != null && xmlCert.getValue() != null) {
                certList.add(xmlCert.getValue());
            }
        }

        return certList;

    }

    /**
     * Analyzes the request headers in order to determine if it comes from an ECP-enabled
     * client and based on this decides whether ECP profile will be used. Subclasses can override
     * the method to control when is the ECP invoked.
     *
     * @param request request to analyze
     * @return whether the request comes from an ECP-enabled client or not
     */
    public static boolean isECPRequest(HttpServletRequest request) {

        String acceptHeader = request.getHeader("Accept");
        String paosHeader = request.getHeader(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_HEADER);
        return acceptHeader != null && paosHeader != null
                && acceptHeader.contains(org.springframework.security.saml.SAMLConstants.PAOS_HTTP_ACCEPT_HEADER)
                && paosHeader.contains(org.opensaml.common.xml.SAMLConstants.PAOS_NS)
                && paosHeader.contains(org.opensaml.common.xml.SAMLConstants.SAML20ECP_NS);

    }

    /**
     * Method helps to identify which endpoint is used to process the current message. It expects a list of potential
     * endpoints based on the current profile and selects the one which uses the specified binding and contains the
     * filterURL in it's name. We presume that each profile-binding combination has a unique name. We also presume
     * that filterURL string is contained exactly once in the endpoint location.
     *
     * @param endpoints      endpoints to check
     * @param messageBinding binding
     * @param filterURL      url of the filter processing the request
     * @param <T>            type of the endpoint
     * @return first endpoint satisfying the filterURL and binding conditions
     * @throws SAMLException in case endpoint can't be found
     */
    public static <T extends Endpoint> T getEndpoint(List<T> endpoints, String messageBinding, String filterURL) throws SAMLException {
        for (T endpoint : endpoints) {
            String binding = getBindingForEndpoint(endpoint);
            // Check that destination and binding matches
            if (binding.equals(messageBinding)) {
                if (endpoint.getLocation().contains(filterURL)) {
                    return endpoint;
                } else if (endpoint.getResponseLocation() != null && endpoint.getResponseLocation().contains(filterURL)) {
                    return endpoint;
                }
            }
        }
        throw new SAMLException("Endpoint with message binding " + messageBinding + " and filter URL " + filterURL + " wasn't found");
    }

    /**
     * Loads IDP descriptor for entity with the given entityID. Fails when it can't be found.
     * @param metadata metadata manager
     * @param idpId entity ID
     * @return descriptor
     * @throws MetadataProviderException in case descriptor can't be found
     */
    public static IDPSSODescriptor getIDPDescriptor(MetadataManager metadata, String idpId) throws MetadataProviderException {
        if (!metadata.isIDPValid(idpId)) {
            logger.debug("IDP name of the authenticated user is not valid", idpId);
            throw new MetadataProviderException("IDP with name " + idpId + " wasn't found in the list of configured IDPs");
        }
        IDPSSODescriptor idpssoDescriptor = (IDPSSODescriptor) metadata.getRole(idpId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        if (idpssoDescriptor == null) {
            throw new MetadataProviderException("Given IDP " + idpId + " doesn't contain any IDPSSODescriptor element");
        }
        return idpssoDescriptor;
    }

    /**
     * Helper method that marshals the given message.
     *
     * @param message message the marshall and serialize
     * @return marshaled message
     * @throws org.opensaml.ws.message.encoder.MessageEncodingException
     *          thrown if the give message can not be marshaled into its DOM representation
     */
    public static Element marshallMessage(XMLObject message) throws MessageEncodingException {
        logger.debug("Marshalling message");
        try {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(message);
            if (marshaller == null) {
                throw new MessageEncodingException("Unable to marshall message, no marshaller registered for message object: "
                                                   + message.getElementQName());
            }
            Element messageElem = marshaller.marshall(message);
            if (logger.isTraceEnabled()) {
                logger.trace("Marshalled message into DOM:\n{}", XMLHelper.nodeToString(messageElem));
            }
            return messageElem;
        } catch (MarshallingException e) {
            logger.error("Encountered error marshalling message to its DOM representation", e);
            throw new MessageEncodingException("Encountered error marshalling message into its DOM representation", e);
        }
    }

}