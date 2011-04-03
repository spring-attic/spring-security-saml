/* Copyright 2010 Vladimir Schaefer
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
 * Constant values for SAML module.
 *
 * @author Vladimir Schaefer
 */
public class SAMLConstants {

    /**
     * Constant identifying special version of the KeyInfoGenerator used to include credentials in generated
     * metadata.
     */
    public static final String SAML_METADATA_KEY_INFO_GENERATOR = "MetadataKeyInfoGenerator";

    public static final String AUTH_N_REQUEST = "AuthNRequest";
    public static final String AUTH_N_RESPONSE = "AuthNResponse";
    public static final String LOGOUT_REQUEST = "LogoutRequest";
    public static final String LOGOUT_RESPONSE = "LogoutResponse";

    public static final String SUCCESS = "SUCCESS";
    public static final String FAILURE = "FAILURE";
    
    public static final String PAOS_HTTP_ACCEPT_HEADER = "application/vnd.paos+xml";
    public static final String PAOS_HTTP_HEADER = "PAOS";

}
