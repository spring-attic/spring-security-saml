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

package org.springframework.security.saml.saml2;

public abstract class ImplementationHolder<T extends ImplementationHolder> implements Saml2Object {

	private Object implementation;
	private String originalXML;

	public Object getImplementation() {
		return implementation;
	}

	public T setImplementation(Object implementation) {
		this.implementation = implementation;
		return _this();
	}

	@Override
	public String getOriginalXML() {
		return originalXML;
	}

	public T setOriginalXML(String originalXML) {
		this.originalXML = originalXML;
		return _this();
	}

	private T _this() {
		return (T)this;
	}
}
