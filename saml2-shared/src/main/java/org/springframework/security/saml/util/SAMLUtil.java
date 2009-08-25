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
package org.springframework.security.saml.util;

import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Utility class for SAML entities
 *
 * @author Vladimir Schäfer
 */
public class SAMLUtil {

    private final static Logger log = LoggerFactory.getLogger(SAMLUtil.class);

    /**
     * Returns assertion consumer service of the given SP for the given binding. If the specified binding
     * can't be found, default binding is returned. In case no binding is marked as default, first binding
     * for assertionConsumber endpoint is used. In case SP doesn't contain any assertionConsumber endpoind
     * exception is thrown.
     *
     * @param descriptor descriptor to search for binding in
     * @param binding    binding type
     * @return consumer service capable of handling the given binding
     * @throws MetadataProviderException in case there is not service capable of handling the binding
     */
    public static AssertionConsumerService getAssertionConsubmerForBinding(SPSSODescriptor descriptor, String binding) throws MetadataProviderException {
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
    public static SingleSignOnService getServiceForBinding(IDPSSODescriptor descriptor, String binding) throws MetadataProviderException {
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
     * Returns default binding supported by IDP.
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
}
