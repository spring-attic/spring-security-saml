/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.saml2.authentication;

public enum StatusCode {

    SUCCESS("urn:oasis:names:tc:SAML:2.0:status:Success"),
    REQUESTER("urn:oasis:names:tc:SAML:2.0:status:Requester"),
    RESPONDER("urn:oasis:names:tc:SAML:2.0:status:Responder"),
    VERSION_MISMATCH("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"),
    AUTHENTICATION_FAILED("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),
    INVALID_ATTRIBUTE("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"),
    INVALID_NAME_ID("urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"),
    NO_AUTH_CONTEXT("urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"),
    NO_AVAILABLE_IDP("urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"),
    NO_PASSIVE("urn:oasis:names:tc:SAML:2.0:status:NoPassive"),
    NO_SUPPORTED_IDP("urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"),
    PARTIAL_LOGOUT("urn:oasis:names:tc:SAML:2.0:status:PartialLogout"),
    PROXY_COUNT_EXCEEDED("urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"),
    REQUEST_DENIED("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"),
    REQUEST_UNSUPPORTED("urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"),
    REQUEST_VERSION_DEPRECATED("urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"),
    REQUEST_VERSION_TOO_HIGH("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"),
    REQUEST_VERSION_TOO_LOW("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"),
    RESOURCE_NOT_RECOGNIZED("urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"),
    TOO_MANY_RESPONSES("urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"),
    UNKNOWN_PRINCIPAL("urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"),
    UNSUPPORTED_BINDING("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"),
    UNKNOWN_STATUS("urn:oasis:names:tc:SAML:2.0:status:Unknown");

    private final String urn;

    StatusCode(String urn) {
        this.urn = urn;
    }

    public static StatusCode fromUrn(String urn) {
        for (StatusCode c : values()) {
            if (c.urn.equalsIgnoreCase(urn)) {
                return c;
            }
        }
        return UNKNOWN_STATUS;
    }

    @Override
    public String toString() {
        return urn;
    }

}
