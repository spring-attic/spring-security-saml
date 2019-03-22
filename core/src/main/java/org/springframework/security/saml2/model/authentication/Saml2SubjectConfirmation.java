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
 * Implementation saml:SubjectConfirmationType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 19, Line 748
 */
public class Saml2SubjectConfirmation {
	private Saml2SubjectConfirmationMethod method;
	private Saml2SubjectConfirmationData data;
	private String nameId;
	private Saml2NameId format;

	public Saml2SubjectConfirmationData getConfirmationData() {
		return data;
	}

	public Saml2SubjectConfirmation setConfirmationData(Saml2SubjectConfirmationData confirmationData) {
		this.data = confirmationData;
		return this;
	}


	public Saml2SubjectConfirmationMethod getMethod() {
		return method;
	}

	public Saml2SubjectConfirmation setMethod(Saml2SubjectConfirmationMethod method) {
		this.method = method;
		return this;
	}

	public String getNameId() {
		return nameId;
	}

	public Saml2SubjectConfirmation setNameId(String nameId) {
		this.nameId = nameId;
		return this;
	}

	public Saml2NameId getFormat() {
		return format;
	}

	public Saml2SubjectConfirmation setFormat(Saml2NameId format) {
		this.format = format;
		return this;
	}
}
