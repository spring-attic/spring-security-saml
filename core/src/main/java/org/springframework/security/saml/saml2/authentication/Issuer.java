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
 * Implementation saml:Issuer as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 15, Line 564
 */
public class Issuer extends NameIdPolicy<Issuer> {
	private String value;
	private String nameQualifier;

	public String getValue() {
		return value;
	}

	public Issuer setValue(String value) {
		this.value = value;
		return this;
	}

	public String getNameQualifier() {
		return nameQualifier;
	}

	public Issuer setNameQualifier(String nameQualifier) {
		this.nameQualifier = nameQualifier;
		return this;
	}
}
