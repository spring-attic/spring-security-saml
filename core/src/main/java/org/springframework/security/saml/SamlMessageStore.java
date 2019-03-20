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

package org.springframework.security.saml;

import java.util.List;

import org.springframework.security.saml.saml2.Saml2Object;

/**
 * Interface to implement a message store.
 * A message store can be used to hold assertions for the purpose of tracking single logout functionality.
 * It can also be used to store AuthnRequest objects for the purpose of tracking responses
 *
 * @param <T>      - the type of object stored
 * @param <Holder> - the specific implementation of the store
 */
public interface SamlMessageStore<T extends Saml2Object, Holder> {

	/**
	 * Returns a list of messages currently stored by the holder
	 *
	 * @param holder - the message store implementation
	 * @return a list of messages, empty if none exist
	 */
	List<T> getMessages(Holder holder);

	/**
	 * Returns true if there are messages in the store for this holder
	 *
	 * @param holder - the message store implementation
	 * @return true if there are messages in the store
	 */
	boolean hasMessages(Holder holder);

	/**
	 * Retrieves a message using its unique message id.
	 * Will return null if no message with that id is stored.
	 *
	 * @param holder - the message store implementation
	 * @param id     - the unique identifier for the message to be retrieved
	 * @return a message or null if none exist
	 */
	T getMessage(Holder holder, String id);

	/**
	 * Removes a message from the store and returns it if found.
	 *
	 * @param holder - the message store implementation
	 * @param id     - the unique identifier for the message to be removed
	 * @return the message that was removed or null if none exist
	 */
	T removeMessage(Holder holder, String id);

	/**
	 * @param holder  - the message store implementation
	 * @param id      - the unique identifier for the message to be added
	 * @param message - the message to be added
	 * @return the message that was added
	 */
	T addMessage(Holder holder, String id, T message);

	/**
	 * Removes and returns the first available message in the store
	 *
	 * @param holder - the message store implementation
	 * @return the first message in the store that was removed or null if none exist
	 */
	T removeFirst(Holder holder);

	/**
	 * Returns the number of messages for a holder
	 *
	 * @param holder the message store implementation
	 * @return the number of messages for that implementation
	 */
	int size(Holder holder);

}
