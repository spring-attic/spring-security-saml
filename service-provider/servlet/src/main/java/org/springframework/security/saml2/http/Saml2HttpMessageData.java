/*
 * Copyright 2002-2019 the original author or authors.
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
 *
 */

package org.springframework.security.saml2.http;

import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;

/**
 * Model object representing an incoming or outgoing SAML message over HTTP
 * using POST or REDIRECT bindings.
 */
public class Saml2HttpMessageData {

	private final Saml2Object samlRequest;
	private final Saml2Object samlResponse;
	private final Saml2Endpoint endpoint;
	private final String relayState;


	public Saml2HttpMessageData(Saml2Object samlRequest,
								Saml2Object samlResponse,
								Saml2Endpoint endpoint, String relayState) {
		this.samlRequest = samlRequest;
		this.samlResponse = samlResponse;
		this.endpoint = endpoint;
		this.relayState = relayState;
	}

	public Saml2Object getSamlRequest() {
		return samlRequest;
	}

	public Saml2Object getSamlResponse() {
		return samlResponse;
	}

	public Saml2Endpoint getEndpoint() {
		return endpoint;
	}

	public String getRelayState() {
		return relayState;
	}
}
