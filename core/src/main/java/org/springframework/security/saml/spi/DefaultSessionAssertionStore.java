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

package org.springframework.security.saml.spi;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.saml2.authentication.Assertion;

/**
 * Manages assertion objects stored in the HTTP session object.
 * Used for handling Single Logout functionality.
 * This store tracks all assertions that were issued under one identity provider session.
 */
public class DefaultSessionAssertionStore implements SamlMessageStore<Assertion, HttpServletRequest> {

	private final String ATTRIBUTE_NAME = getClass().getName() + ".assertions";

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<Assertion> getMessages(HttpServletRequest request) {
		return getDataMap(request).values().stream().collect(Collectors.toList());
	}

	protected Map<String, Assertion> getDataMap(HttpServletRequest request) {
		return getDataMap(request, false);
	}

	protected Map<String, Assertion> getDataMap(HttpServletRequest request, boolean createSession) {
		HttpSession session = request.getSession(createSession);
		if (session == null) {
			return Collections.emptyMap();
		}
		Map<String, Assertion> data;
		synchronized (session) {
			data = (Map<String, Assertion>) session.getAttribute(ATTRIBUTE_NAME);
			if (data == null) {
				data = new LinkedHashMap<>();
				session.setAttribute(ATTRIBUTE_NAME, data);
			}
		}
		return data;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasMessages(HttpServletRequest request) {
		return !getDataMap(request).values().isEmpty();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Assertion getMessage(HttpServletRequest request, String id) {
		return getDataMap(request).get(id);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Assertion removeMessage(HttpServletRequest request, String id) {
		return getDataMap(request).remove(id);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Assertion addMessage(HttpServletRequest request,
								String id,
								Assertion assertion) {
		return getDataMap(request, true).put(id, assertion);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized Assertion removeFirst(HttpServletRequest request) {
		Collection<Assertion> values = getDataMap(request).values();
		Assertion first = null;
		if (values != null && !values.isEmpty()) {
			first = values.stream().findFirst().get();
			removeMessage(request, first.getId());
		}
		return first;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int size(HttpServletRequest request) {
		return getDataMap(request).size();
	}
}
