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

public enum LogoutReason {

	USER("urn:oasis:names:tc:SAML:2.0:logout:user"),
	ADMIN("urn:oasis:names:tc:SAML:2.0:logout:admin"),
	UNKNOWN("urn:oasis:names:tc:SAML:2.0:logout:unknown");


	private final String urn;

	LogoutReason(String urn) {
		this.urn = urn;
	}

	public static LogoutReason fromUrn(String urn) {
		for (LogoutReason reason : values()) {
			if (reason.urn.equals(urn)) {
				return reason;
			}
		}
		return UNKNOWN;
	}
}
