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
package org.springframework.security.saml.util;

import java.io.StringReader;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.xml.transform.stream.StreamSource;

import org.springframework.security.saml.saml2.Namespace;

import org.hamcrest.Matcher;
import org.w3c.dom.Node;
import org.xmlunit.xpath.JAXPXPathEngine;
import org.xmlunit.xpath.XPathEngine;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class XmlTestUtil {

	private static XPathEngine engine;

	static {
		engine = new JAXPXPathEngine();
		HashMap<String, String> nsContext = new HashMap<>();
		nsContext.put("md", Namespace.NS_METADATA);
		nsContext.put("ds", Namespace.NS_SIGNATURE);
		nsContext.put("samlp", Namespace.NS_PROTOCOL);
		nsContext.put("saml", Namespace.NS_ASSERTION);
		nsContext.put("idpdisc", Namespace.NS_IDP_DISCOVERY);
		nsContext.put("init", Namespace.NS_REQUEST_INIT);
		engine.setNamespaceContext(nsContext);
	}

	public static void assertNodeAttribute(Node node, String attribute, String expected) {
		Node attr = node.getAttributes().getNamedItem(attribute);
		assertEquals(expected, attr.getTextContent());
	}

	public static void assertNodeAttribute(Node node, String attribute, Matcher<String> matcher) {
		Node attr = node.getAttributes().getNamedItem(attribute);
		if (attr == null) {
			assertThat(null, matcher);
		}
		else {
			assertThat(attr.getTextContent(), matcher);
		}

	}

	public static void assertTextNodeValue(Node node, Matcher<String> matcher) {
		assertThat(node.getNodeValue(), matcher);
	}

	public static Iterable<Node> assertNodeCount(String xml, String xPath, int expected) {
		assertThat("XML cannot be null", xml, notNullValue(String.class));
		Iterable<Node> nodes = getNodes(xml, xPath);
		if (nodes == null) {
			assertEquals(expected, 0);
		}
		AtomicInteger count = new AtomicInteger(0);
		nodes.forEach(p -> count.incrementAndGet());
		assertEquals(
			expected,
			count.get()
		);
		return nodes;
	}

	public static Iterable<Node> getNodes(String xml, String xPath) {
		return engine
			.selectNodes(
				xPath,
				new StreamSource(
					new StringReader(xml)
				)
			);
	}
}
