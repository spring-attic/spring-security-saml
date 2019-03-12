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

import org.springframework.security.saml.saml2.Saml2Object;

/**
 * Represents metadata for a
 * <ul>
 * <li>SSO Service Provider</li>
 * <li>SSO Identity Provider</li>
 * </ul>
 * May be chained if read from EntitiesDescriptor element.
 *
 * Currently does <b>not support</b> metadata for
 * <ul>
 * <li>Authentication Authority</li>
 * <li>Attribute Authority</li>
 * <li>Policy Decision Point</li>
 * <li>Affiliation</li>
 * </ul>
 */
public class Metadata<T extends EntityDescriptor<T>> extends EntityDescriptor<T> implements Saml2Object {
	/*
	 * In case of parsing EntitiesDescriptor, we can have more than one provider
	 */
	private T next = null;

	public Metadata() {
	}

	public Metadata(Metadata<T> other) {
		super(other);
		this.next = other.next;
	}

	public T getNext() {
		return next;
	}

	public Metadata<T> setNext(T next) {
		this.next = next;
		return this;
	}

	public boolean hasNext() {
		return next != null;
	}
}
