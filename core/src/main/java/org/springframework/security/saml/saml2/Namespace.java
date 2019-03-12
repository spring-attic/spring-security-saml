/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml.saml2;

public class Namespace {

	public static final String NS_ASSERTION_PREFIX = "saml:";
	public static final String NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

	public static final String NS_PROTOCOL_PREFIX = "samlp:";
	public static final String NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

	public static final String NS_METADATA_PREFIX = "md:";
	public static final String NS_METADATA = "urn:oasis:names:tc:SAML:2.0:metadata";

	public static final String NS_SIGNATURE_PREFIX = "ds:";
	public static final String NS_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#";

	public static final String NS_ENCRYPTION_PREFIX = "xenc:";
	public static final String NS_ENCRYPTION = "http://www.w3.org/2001/04/xmlenc#";

	public static final String NS_SCHEMA_PREFIX = "xs:";
	public static final String NS_SCHEMA = "http://www.w3.org/2001/XMLSchema";

	public static final String NS_IDP_DISCOVERY =
		"urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol";
	public static final String NS_REQUEST_INIT = "urn:oasis:names:tc:SAML:profiles:SSO:request-init";

}
