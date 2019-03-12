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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Implementation saml:SubjectType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 18, Line 708
 */
public class Subject {

	/**
	 * BaseID, NameID or EncryptedID
	 */
	private NameIdPrincipal principal;
	private List<SubjectConfirmation> confirmations = new LinkedList<>();

	public NameIdPrincipal getPrincipal() {
		return principal;
	}

	public Subject setPrincipal(NameIdPrincipal principal) {
		this.principal = principal;
		return this;
	}

	public List<SubjectConfirmation> getConfirmations() {
		return Collections.unmodifiableList(confirmations);
	}

	public Subject setConfirmations(List<SubjectConfirmation> confirmations) {
		this.confirmations.clear();
		if (confirmations != null) {
			this.confirmations.addAll(confirmations);
		}
		return this;
	}

	public Subject addConfirmation(SubjectConfirmation subjectConfirmation) {
		if (subjectConfirmation != null) {
			this.confirmations.add(subjectConfirmation);
		}
		return this;
	}
}
