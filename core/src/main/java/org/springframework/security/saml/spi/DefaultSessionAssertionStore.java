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

package org.springframework.security.saml.spi;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.saml2.authentication.Assertion;

public class DefaultSessionAssertionStore implements SamlMessageStore<Assertion, HttpServletRequest> {

	private String ATTRIBUTE_NAME = getClass().getName() + ".assertions";

	protected Map<String, Assertion> getDataMap(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return Collections.emptyMap();
		}
		Map<String, Assertion> data;
		synchronized (session) {
			data = (Map<String, Assertion>) session.getAttribute(ATTRIBUTE_NAME);
			if (data == null) {
				data = new ConcurrentHashMap<>();
				session.setAttribute(ATTRIBUTE_NAME, data);
			}
		}
		return data;
	}

	@Override
	public List<Assertion> getMessages(HttpServletRequest request) {
		return (List<Assertion>) getDataMap(request).values();
	}

	@Override
	public Assertion getMessage(HttpServletRequest request, String id) {
		return getDataMap(request).get(id);
	}

	@Override
	public Assertion removeMessage(HttpServletRequest request, String id) {
		return getDataMap(request).remove(id);
	}

	@Override
	public Assertion addMessage(HttpServletRequest request,
								String id,
								Assertion assertion) {
		return getDataMap(request).put(id, assertion);
	}
}
