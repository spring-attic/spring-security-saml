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
package org.springframework.security.saml;

import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.storage.HttpSessionStorage;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;

import javax.servlet.http.HttpServletRequest;

/**
 * Filter processes arriving SAML messages by delegating to the WebSSOProfile. After the SAMLAuthenticationToken
 * is obtained, authentication providers are asked to authenticate it.
 *
 * @author Vladimir Schäfer
 */
public class SAMLProcessingFilter extends AbstractProcessingFilter {

    /**
     * Profile to delegate SAML parsing to
     */
    private SAMLProcessor processor;

    private static final String DEFAUL_URL = "/saml/SSO";

    /**
     * In case the login attribute is not present it is presumed that the call is made from the remote IDP
     * and contains a SAML assertion which is processed and authenticated.
     *
     * @param request request
     * @return authentication object in case SAML data was found and valid
     * @throws AuthenticationException authentication failture
     */
    public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        try {
            if (processor == null) {
                throw new SAMLRuntimeException("SAMLProcessor instance wasn't set");
            }
            logger.debug("Attempting SAML2 authentiction");
            BasicSAMLMessageContext samlMessageContext = processor.processSSO(request);
            HttpSessionStorage storage = new HttpSessionStorage(request);
            SAMLAuthenticationToken token = new SAMLAuthenticationToken(samlMessageContext, storage);
            return getAuthenticationManager().authenticate(token);
        } catch (SAMLException e) {
            throw new SAMLRuntimeException("Incoming SAML message is invalid");
        } catch (MetadataProviderException e) {
            throw new SAMLRuntimeException("Error determining metadata contracts");
        } catch (MessageDecodingException e) {
            throw new SAMLRuntimeException("Error decoding incoming SAML message");
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new SAMLRuntimeException("Incoming SAML message is invalid");
        }
    }

    public String getDefaultFilterProcessesUrl() {
        return DEFAUL_URL;
    }

    public int getOrder() {
        return FilterChainOrder.AUTHENTICATION_PROCESSING_FILTER;
    }

    public void setSAMLProcessor(SAMLProcessor processor) {
        this.processor = processor;
    }
}
