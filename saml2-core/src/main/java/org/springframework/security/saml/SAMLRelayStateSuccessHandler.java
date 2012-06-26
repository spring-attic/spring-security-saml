/* Copyright 2010 Vladimir Schafer
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Implementation of a success handler which interprets meaning of the RelayState inside SAMLCredential
 * as an URL to redirect user to.
 *
 * @author Vladimir Schafer
 */
public class SAMLRelayStateSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    /**
     * Class logger.
     */
    protected final static Logger log = LoggerFactory.getLogger(SAMLRelayStateSuccessHandler.class);

    /**
     * Implementation tries to load RelayString from the SAMLCredential authentication object and in case the state
     * is present uses it as the target URL. In case the state is missing behaviour is the same as of the
     * SavedRequestAwareAuthenticationSuccessHandler.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {

        Object credentials = authentication.getCredentials();
        if (credentials instanceof SAMLCredential) {
            SAMLCredential samlCredential = (SAMLCredential) credentials;
            String relayStateURL = getTargetURL(samlCredential.getRelayState());
            if (relayStateURL != null) {
                log.debug("Redirecting to RelayState Url: " + relayStateURL);
                getRedirectStrategy().sendRedirect(request, response, relayStateURL);
                return;
            }
        }

        super.onAuthenticationSuccess(request, response, authentication);

    }

    /**
     * Method is responsible for processing relayState and returning URL the system can redirect to. Method
     * can decide to ignore the relayState and redirect user to default location by returning null.
     *
     * @param relayState relay state to process, can be null
     * @return null to ignore the state, URL to redirect to otherwise
     */
    protected String getTargetURL(String relayState) {
        return relayState;
    }

}