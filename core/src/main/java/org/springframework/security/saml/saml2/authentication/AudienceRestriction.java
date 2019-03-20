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

/**
 * Implementation saml:AudienceRestrictionType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 24, Line 976
 */
public class AudienceRestriction extends AssertionCondition<AudienceRestriction, String> {

	private List<String> audiences = new LinkedList<>();

	public List<String> getAudiences() {
		return Collections.unmodifiableList(audiences);
	}

	public AudienceRestriction setAudiences(List<String> audiences) {
		this.audiences.clear();
		this.audiences.addAll(audiences);
		return _this();
	}

	@Override
	protected boolean internalEvaluate(String evaluationCriteria) {
		return audiences.contains(evaluationCriteria);
	}

	public AudienceRestriction addAudience(String audience) {
		this.audiences.add(audience);
		return _this();
	}
}
