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

package org.springframework.security.saml2.spi.keycloak;

import org.w3c.dom.Document;

public class Saml2ObjectHolder {
	private final Document document;
	private final Object saml2Object;

	public Saml2ObjectHolder(Document document, Object saml2Object) {
		this.document = document;
		this.saml2Object = saml2Object;
	}

	public Document getDocument() {
		return document;
	}

	public Object getSaml2Object() {
		return saml2Object;
	}
}
