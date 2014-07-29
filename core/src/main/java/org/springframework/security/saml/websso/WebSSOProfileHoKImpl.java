/* Copyright 2009 Vladimir Schafer
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

import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.util.SAMLUtil;

/**
 * Class implements WebSSO profile and offers capabilities for SP initialized SSO and
 * process Response coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect
 * bindings are supported.
 *
 * @author Vladimir Schafer
 */
public class WebSSOProfileHoKImpl extends WebSSOProfileImpl {

    @Override
    public String getProfileIdentifier() {
        return SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI;
    }

    @Override
    protected boolean isEndpointSupported(SingleSignOnService endpoint) throws MetadataProviderException {

        // Only HoK endpoints are supported
        if (!SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI.equals(endpoint.getBinding())) {
            return false;
        }

        String binding = SAMLUtil.getBindingForEndpoint(endpoint);
        return org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI.equals(binding) ||
                org.opensaml.common.xml.SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(binding) ||
                org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding);

    }

    @Override
    protected boolean isEndpointSupported(AssertionConsumerService endpoint) throws MetadataProviderException {

        // Only HoK endpoints are supported
        if (!SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI.equals(endpoint.getBinding())) {
            return false;
        }

        String binding = SAMLUtil.getBindingForEndpoint(endpoint);
        return org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI.equals(binding) ||
                org.opensaml.common.xml.SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(binding);

    }

}