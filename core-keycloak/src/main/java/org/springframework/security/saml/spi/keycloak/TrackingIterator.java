/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.spi.keycloak;

import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Consumer;

class TrackingIterator<T> implements Iterator<T> {

	private final List<T> iterator;
	private int index = -1;

	TrackingIterator(List<T> iterator) {
		this.iterator = iterator;
	}

	public int getCurrentIndex() {
		return index;
	}

	void reset() {
		index = -1;
	}	public T getCurrent() {
		try {
			return iterator.get(index);
		} catch (IndexOutOfBoundsException e) {
			throw new NoSuchElementException("Index not pointing to an element");
		}
	}



	@Override
	public boolean hasNext() {
		return (index + 1) < iterator.size();
	}

	@Override
	public T next() {
		index++;
		return getCurrent();
	}

	@Override
	public void remove() {
		//no op
	}

	@Override
	public void forEachRemaining(Consumer<? super T> action) {
		while (hasNext()) {
			action.accept(next());
		}
	}
}
