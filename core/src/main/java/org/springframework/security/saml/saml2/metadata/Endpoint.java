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
package org.springframework.security.saml.saml2.metadata;

/**
 * Defines EndpointType as defined by
 * https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf
 * Page 9, Line 294
 */
public class Endpoint {

	private int index = 0;
	private boolean isDefault;
	private Binding binding;
	private String location;
	private String responseLocation;

	public int getIndex() {
		return index;
	}

	public Endpoint setIndex(int index) {
		this.index = index;
		return this;
	}

	public boolean isDefault() {
		return isDefault;
	}

	public Endpoint setDefault(boolean isDefault) {
		this.isDefault = isDefault;
		return this;
	}

	public Binding getBinding() {
		return binding;
	}

	public Endpoint setBinding(Binding binding) {
		this.binding = binding;
		return this;
	}

	public String getLocation() {
		return location;
	}

	public Endpoint setLocation(String location) {
		this.location = location;
		return this;
	}

	public String getResponseLocation() {
		return responseLocation;
	}

	public Endpoint setResponseLocation(String responseLocation) {
		this.responseLocation = responseLocation;
		return this;
	}

	@Override
	public String toString() {
		final StringBuffer sb = new StringBuffer("Endpoint{");
		sb.append("index=").append(getIndex());
		sb.append(", isDefault=").append(isDefault());
		sb.append(", binding=").append(getBinding());
		sb.append(", location='").append(getLocation()).append('\'');
		sb.append('}');
		return sb.toString();
	}
}
