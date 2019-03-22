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

package org.springframework.security.saml2.model.attribute;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.springframework.security.saml2.model.attribute.Saml2AttributeNameFormat.UNSPECIFIED;

/**
 * Implementation saml:AttributeType as defined by
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 30, Line 1284
 */
public class Saml2Attribute {

	private String name;
	private String friendlyName;
	private List<Object> values = new LinkedList<>();
	private Saml2AttributeNameFormat nameFormat = UNSPECIFIED;
	private boolean required;


	public String getName() {
		return name;
	}

	public Saml2Attribute setName(String name) {
		this.name = name;
		return this;
	}

	public List<Object> getValues() {
		return Collections.unmodifiableList(values);
	}

	public Saml2Attribute setValues(List<Object> values) {
		this.values.clear();
		this.values.addAll(values);
		return this;
	}

	public Saml2AttributeNameFormat getNameFormat() {
		return nameFormat;
	}

	public Saml2Attribute setNameFormat(Saml2AttributeNameFormat nameFormat) {
		this.nameFormat = nameFormat;
		return this;
	}

	public String getFriendlyName() {
		return friendlyName;
	}

	public Saml2Attribute setFriendlyName(String friendlyName) {
		this.friendlyName = friendlyName;
		return this;
	}

	public boolean isRequired() {
		return required;
	}

	public Saml2Attribute setRequired(boolean required) {
		this.required = required;
		return this;
	}

	public Saml2Attribute addValues(Object... values) {
		this.values.addAll(Arrays.asList(values));
		return this;
	}
}
