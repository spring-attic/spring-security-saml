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

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.util.Assert;
import sun.misc.Regexp;

import javax.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for SAML entities
 *
 * @author Vladimir Schaefer
 */
public class SAMLUtil {

    private final static Logger log = LoggerFactory.getLogger(SAMLUtil.class);

    /**
     * Returns assertion consumer service of the given SP for the given binding. If the specified binding
     * can't be found, default binding is returned. In case no binding is marked as default, first binding
     * for assertionConsumer endpoint is used. In case SP doesn't contain any assertionConsumer endpoint
     * exception is thrown.
     *
     * @param descriptor descriptor to search for binding in
     * @param binding    binding type
     * @return consumer service capable of handling the given binding
     * @throws MetadataProviderException in case there is not service capable of handling the binding
     */
    public static AssertionConsumerService getAssertionConsumerForBinding(SPSSODescriptor descriptor, String binding) throws MetadataProviderException {
        List<AssertionConsumerService> services = descriptor.getAssertionConsumerServices();
        AssertionConsumerService foundService = null;
        for (AssertionConsumerService service : services) {
            if (binding.equals(service.getBinding())) {
                return service;
            } else if (foundService == null) {
                foundService = service;
            }
        }

        if (descriptor.getDefaultAssertionConsumerService() != null) {
            return descriptor.getDefaultAssertionConsumerService();
        } else if (foundService != null) {
            return foundService;
        }

        log.debug("No binding found for SP with binding " + binding);
        throw new MetadataProviderException("Binding " + binding + " is not supported for this SP and no other was found");
    }

    /**
     * Returns SSOService for given binding of the IDP.
     *
     * @param descriptor IDP to search for service in
     * @param binding    binding supported by the service
     * @return SSO service capable of handling the given binding
     * @throws MetadataProviderException if the service can't be determined
     */
    public static SingleSignOnService getSSOServiceForBinding(IDPSSODescriptor descriptor, String binding) throws MetadataProviderException {
        List<SingleSignOnService> services = descriptor.getSingleSignOnServices();
        for (SingleSignOnService service : services) {
            if (binding.equals(service.getBinding())) {
                return service;
            }
        }
        log.debug("No binding found for IDP with binding " + binding);
        throw new MetadataProviderException("Binding " + binding + " is not supported for this IDP");
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
        log.debug("No binding found for IDP with binding " + binding);
        throw new MetadataProviderException("Binding " + binding + " is not supported for this IDP");
    }

    public static String getLoginBinding(WebSSOProfileOptions options, IDPSSODescriptor idp, SPSSODescriptor sp) throws MetadataProviderException {

        String requiredBinding = options.getBinding();
        for (Endpoint idpEndpoint : idp.getSingleSignOnServices()) {
            if (idpEndpoint.getBinding().equals(requiredBinding)) {
                return requiredBinding;
            }
        }

        return SAMLUtil.getDefaultBinding(idp);
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
            log.error("Could not find an IDPSSODescriptor in metadata.");
            throw new MessageDecodingException("Could not find an IDPSSODescriptor in metadata.");
        }

        return idpSSODescriptor;

    }

    public static ArtifactResolutionService getArtifactResolutionService(IDPSSODescriptor idpssoDescriptor, int endpointIndex) throws MessageDecodingException {

        List<ArtifactResolutionService> artifactResolutionServices = idpssoDescriptor.getArtifactResolutionServices();
        if (artifactResolutionServices == null || artifactResolutionServices.size() == 0) {
            log.error("Could not find any artifact resolution services in metadata.");
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

}