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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.joda.time.DateTime;

/**
 * Implementation saml:ConditionsType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 22, Line 897
 */
public class Conditions {

	private DateTime notBefore;
	private DateTime notOnOrAfter;
	private List<AssertionCondition> criteria = new LinkedList<>();

	public DateTime getNotBefore() {
		return notBefore;
	}

	public Conditions setNotBefore(DateTime notBefore) {
		this.notBefore = notBefore;
		return this;
	}

	public DateTime getNotOnOrAfter() {
		return notOnOrAfter;
	}

	public Conditions setNotOnOrAfter(DateTime notOnOrAfter) {
		this.notOnOrAfter = notOnOrAfter;
		return this;
	}

	public List<AssertionCondition> getCriteria() {
		return Collections.unmodifiableList(criteria);
	}

	public Conditions setCriteria(List<AssertionCondition> criteria) {
		this.criteria.clear();
		this.criteria.addAll(criteria);
		return this;
	}

	public Conditions addCriteria(AssertionCondition condition) {
		this.criteria.add(condition);
		return this;
	}
}
