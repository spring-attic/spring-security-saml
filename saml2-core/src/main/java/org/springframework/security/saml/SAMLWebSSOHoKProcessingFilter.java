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

/**
 * Filter processes messages sent from IDP as part of the WebSSO Holder-of-Key profile.
 *
 * @author Vladimir Schäfer
 */
public class SAMLWebSSOHoKProcessingFilter extends SAMLProcessingFilter {

    /**
     * URL for Web SSO HoK profile responses or unsolicited requests
     */
    public static final String WEBSSO_HOK_URL = "/saml/HoKSSO";

    /**
     * Default constructor.
     */
    public SAMLWebSSOHoKProcessingFilter() {
        super(WEBSSO_HOK_URL);
    }

    /**
     * Name of the WebSSO HoK profile this filter processes.
     *
     * @return profile name
     * @see SAMLConstants#SAML2_HOK_WEBSSO_PROFILE_URI
     */
    protected String getProfileName() {
        return SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI;
    }

}