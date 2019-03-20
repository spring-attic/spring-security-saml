/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.springframework.security.saml.saml2.authentication;

/**
 * Implementation samlp:StatusCode as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 39, Line 1683
 */
public enum StatusCode {

	SUCCESS(
		"urn:oasis:names:tc:SAML:2.0:status:Success",
		"The request succeeded."
	),
	REQUESTER(
		"urn:oasis:names:tc:SAML:2.0:status:Requester",
		"The request could not be performed due to an error on the part of the requester."
	),
	RESPONDER(
		"urn:oasis:names:tc:SAML:2.0:status:Responder",
		"The request could not be performed due to an error on the part of the SAML responder or SAML authority."
	),
	VERSION_MISMATCH(
		"urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
		"The SAML responder could not process the request because the version of the request message was incorrect."
	),
	AUTHENTICATION_FAILED(
		"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
		"The responding provider was unable to successfully authenticate the principal."
	),
	INVALID_ATTRIBUTE(
		"urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
		"Unexpected or invalid content was encountered within an attribute or attribute value."
	),
	INVALID_NAME_ID(
		"urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
		"The responding provider cannot or will not support the requested name identifier policy."
	),
	NO_AUTH_CONTEXT(
		"urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
		"The specified authentication context requirements cannot be met by the responder."
	),
	NO_AVAILABLE_IDP(
		"urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
		"No available identity providers from the supplied Loc or IDPList values."
	),
	NO_PASSIVE(
		"urn:oasis:names:tc:SAML:2.0:status:NoPassive",
		"Unable to authenticate principal passively."
	),
	NO_SUPPORTED_IDP(
		"urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
		"No supported identity providers from the supplied Loc or IDPList values."
	),
	PARTIAL_LOGOUT(
		"urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
		"Federated logout was only partially successful."
	),
	PROXY_COUNT_EXCEEDED(
		"urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
		"Unable to authenticate principal and forwarding to proxy is prohibited."
	),
	REQUEST_DENIED(
		"urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
		"Unable to process request, request denied."
	),
	REQUEST_UNSUPPORTED(
		"urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
		"Unable to process request, request denied."
	),
	REQUEST_VERSION_DEPRECATED(
		"urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated",
		"Request version is deprecated."
	),
	REQUEST_VERSION_TOO_HIGH(
		"urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh",
		"Request version is not supported, too high."
	),
	REQUEST_VERSION_TOO_LOW(
		"urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
		"Request version is not supported, too low."
	),
	RESOURCE_NOT_RECOGNIZED(
		"urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized",
		"The resource identified in the request is not recognized."
	),
	TOO_MANY_RESPONSES(
		"urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
		"Unable to produce response message, too many responses to process."
	),
	UNKNOWN_PRINCIPAL(
		"urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
		"Principal not recognized."
	),
	UNSUPPORTED_BINDING(
		"urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding", "Requested binding not supported."
	),
	UNKNOWN_STATUS(
		"urn:oasis:names:tc:SAML:2.0:status:Unknown",
		"Unknown error occurred."
	);

	private final String urn;
	private final String description;

	StatusCode(String urn, String description) {
		this.urn = urn;
		this.description = description;
	}

	public static StatusCode fromUrn(String urn) {
		for (StatusCode c : values()) {
			if (c.urn.equalsIgnoreCase(urn)) {
				return c;
			}
		}
		return UNKNOWN_STATUS;
	}

	public String getDescription() {
		return description;
	}

	@Override
	public String toString() {
		return urn;
	}

}
