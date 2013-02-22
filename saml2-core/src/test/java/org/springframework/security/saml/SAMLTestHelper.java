/* Copyright 2013 Vladimir Schäfer
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
package org.springframework.security.saml;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;

import javax.servlet.http.HttpServletRequest;

import static org.easymock.EasyMock.expect;

/**
 * Helper for SAML tests.
 */
public class SAMLTestHelper {

    private static XMLObjectBuilderFactory builderFactory;

    /**
     * Helper method for setting of request parameters for local context population.
     *
     * @param request
     * @param requestURI
     * @param localEntityId
     */
    public static void setLocalContextParameters(HttpServletRequest request, String requestURI, String localEntityId) {
        expect(request.isSecure()).andReturn(false);
        expect(request.getContextPath()).andReturn("");
        request.setAttribute(SAMLConstants.LOCAL_CONTEXT_PATH, "");
        expect(request.getRequestURI()).andReturn(requestURI);
        expect(request.getAttribute(SAMLConstants.LOCAL_ENTITY_ID)).andReturn(localEntityId);
        expect(request.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
    }

    /**
     * Helper method for setting of request parameters for peer context population.
     *
     * @param request
     * @param idpParameter
     * @param peerEntityId
     */
    public static void setPeerContextParameters(HttpServletRequest request, String idpParameter, String peerEntityId) {
        expect(request.getAttribute(org.springframework.security.saml.SAMLConstants.PEER_ENTITY_ID)).andReturn(peerEntityId);
        expect(request.getParameter(SAMLEntryPoint.IDP_PARAMETER)).andReturn(idpParameter);
    }

    /**
     * Helper method providing factory for construction of SAML messages.
     *
     * @return builder factory
     * @throws Exception
     */
    public static XMLObjectBuilderFactory getBuilderFactory() {
        if (builderFactory == null) {
            try {
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                throw new RuntimeException("Error creating builder factory");
            }
            builderFactory = Configuration.getBuilderFactory();
        }
        return builderFactory;
    }

}