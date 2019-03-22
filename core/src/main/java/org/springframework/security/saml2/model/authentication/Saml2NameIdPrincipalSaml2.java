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
package org.springframework.security.saml2.model.authentication;

import org.springframework.security.saml2.model.metadata.Saml2NameId;

/**
 * Value inside a Subject holding the asserted entity, such as username
 * See saml:SubjectType
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 18, Line 707
 */
public class Saml2NameIdPrincipalSaml2 extends Saml2SubjectPrincipal<Saml2NameIdPrincipalSaml2> {
	private String nameQualifier;
	private String spNameQualifier;
	private Saml2NameId format;

	private String spProvidedId;

	public String getNameQualifier() {
		return nameQualifier;
	}

	public Saml2NameIdPrincipalSaml2 setNameQualifier(String nameQualifier) {
		this.nameQualifier = nameQualifier;
		return _this();
	}

	public String getSpNameQualifier() {
		return spNameQualifier;
	}

	public Saml2NameIdPrincipalSaml2 setSpNameQualifier(String spNameQualifier) {
		this.spNameQualifier = spNameQualifier;
		return _this();
	}

	public Saml2NameId getFormat() {
		return format;
	}

	public Saml2NameIdPrincipalSaml2 setFormat(Saml2NameId format) {
		this.format = format;
		return _this();
	}

	public String getSpProvidedId() {
		return spProvidedId;
	}

	public Saml2NameIdPrincipalSaml2 setSpProvidedId(String spProvidedId) {
		this.spProvidedId = spProvidedId;
		return _this();
	}
}
