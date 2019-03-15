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

import org.springframework.security.saml.saml2.metadata.NameId;

/**
 * Value inside a Subject holding the asserted entity, such as username
 * See saml:SubjectType
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 18, Line 707
 */
public class NameIdPrincipal extends SubjectPrincipal<NameIdPrincipal> {
	private String nameQualifier;
	private String spNameQualifier;
	private NameId format;

	private String spProvidedId;

	public String getNameQualifier() {
		return nameQualifier;
	}

	public NameIdPrincipal setNameQualifier(String nameQualifier) {
		this.nameQualifier = nameQualifier;
		return _this();
	}

	public String getSpNameQualifier() {
		return spNameQualifier;
	}

	public NameIdPrincipal setSpNameQualifier(String spNameQualifier) {
		this.spNameQualifier = spNameQualifier;
		return _this();
	}

	public NameId getFormat() {
		return format;
	}

	public NameIdPrincipal setFormat(NameId format) {
		this.format = format;
		return _this();
	}

	public String getSpProvidedId() {
		return spProvidedId;
	}

	public NameIdPrincipal setSpProvidedId(String spProvidedId) {
		this.spProvidedId = spProvidedId;
		return _this();
	}
}
