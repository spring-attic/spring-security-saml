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
package org.springframework.security.saml.saml2.authentication;

/**
 * This is either a BaseID, NameID or EncryptedID
 * See saml:SubjectType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 18, Line 708
 */
public abstract class SubjectPrincipal<T extends SubjectPrincipal> {

	private String value;

	public String getValue() {
		return value;
	}

	public T setValue(String value) {
		this.value = value;
		return _this();
	}

	@SuppressWarnings("checked")
	protected T _this() {
		return (T) this;
	}
}
