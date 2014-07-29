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

import org.opensaml.saml2.core.AuthnRequest;

import javax.xml.namespace.QName;

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

    /**
     * Identifier of the WebSSO profile.
     */
    public static final String SAML2_WEBSSO_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser";

    /**
     * Identifier of the WebSSO HoK profile.
     */
    public static final String SAML2_HOK_WEBSSO_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser";

    /**
     * Identifier of the ECP profile.
     */
    public static final String SAML2_ECP_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";

    /**
     * Identifier of the Artifact profile.
     */
    public static final String SAML2_ARTIFACT_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:profiles:artifact";

    /**
     * Identifier of the Single Logout profile.
     */
    public static final String SAML2_SLO_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:logout";

    public static final String AUTH_N_REQUEST = "AuthNRequest";
    public static final String AUTH_N_RESPONSE = "AuthNResponse";
    public static final String LOGOUT_REQUEST = "LogoutRequest";
    public static final String LOGOUT_RESPONSE = "LogoutResponse";

    public static final String SUCCESS = "SUCCESS";
    public static final String FAILURE = "FAILURE";
    
    public static final String PAOS_HTTP_ACCEPT_HEADER = "application/vnd.paos+xml";
    public static final String PAOS_HTTP_HEADER = "PAOS";

    /**
     * Used as attribute inside HttpServletRequest to indicate required local entity id to the context provider.
     */
    public static final String LOCAL_ENTITY_ID = "localEntityId";

    /**
     * Used as attribute inside HttpServletRequest to indicate required peer entity id to the context provider.
     */
    public static final String PEER_ENTITY_ID = "peerEntityId";

    /**
     * Used to store context path inside InTransport
     */
    public static final String LOCAL_CONTEXT_PATH = "localContextPath";

    /**
     * Qualified name of the attribute used to convey binding information in the Holder of Key metadata endpoint.
     */
    public static final QName WEBSSO_HOK_METADATA_ATT_NAME = new QName(org.springframework.security.saml.SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI, AuthnRequest.PROTOCOL_BINDING_ATTRIB_NAME);

}
