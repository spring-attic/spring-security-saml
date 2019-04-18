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

package org.springframework.security.saml2.spi.opensaml;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.model.authentication.Saml2Issuer;
import org.springframework.security.saml2.model.authentication.Saml2Scoping;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.util.StreamUtils;
import org.w3c.dom.Node;

import java.io.IOException;
import java.time.Clock;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml2.util.XmlTestUtil.getNodes;

class OpenSaml2ImplementationTest {

	private OpenSaml2Implementation subject = new OpenSaml2Implementation(Clock.systemDefaultZone());

	{
		subject.bootstrap();
	}

	@Test
	public void authenticationRequestWithScopingToXml() {
		Saml2AuthenticationRequest authenticationRequest = new Saml2AuthenticationRequest();
		String requesterId = "http://requesterId";
		String idpId = "http://idp";
		authenticationRequest
			.setBinding(Saml2Binding.REDIRECT)
			.setScoping(new Saml2Scoping(
				Collections.singletonList(idpId),
				Collections.singletonList(requesterId),
				new Integer(5)))
			.setAssertionConsumerService(saml2Endpoint("http://assertionConsumerService"))
			.setDestination(saml2Endpoint("http://destination"))
			.setIssuer(new Saml2Issuer());

		String xml = subject.toXml(authenticationRequest);

		assertNodeCount(xml, "//saml2p:Scoping", 1);

		Iterable<Node> nodes = getNodes(xml, "//saml2p:Scoping");
		String textContent = nodes.iterator().next().getAttributes().getNamedItem("ProxyCount").getTextContent();
		assertEquals("5", textContent);

		nodes = getNodes(xml, "//saml2p:RequesterID");
		textContent = nodes.iterator().next().getTextContent();
		assertEquals(requesterId, textContent);

		nodes = getNodes(xml, "//saml2p:IDPEntry");
		textContent = nodes.iterator().next().getAttributes().getNamedItem("ProviderID").getTextContent();
		assertEquals(idpId, textContent);
	}

	@Test
	public void resolveAuthnRequestWithScoping() throws IOException {
		Saml2Scoping scoping =
			parseSaml2Scoping("authn_request_with_scoping.xml");

		List<String> idpList = scoping.getIdpList();
		assertEquals(1, idpList.size());
		assertEquals("http://idp", idpList.get(0));

		List<String> requesterIds = scoping.getRequesterIds();
		assertEquals(1, requesterIds.size());
		assertEquals("http://requesterId", requesterIds.get(0));

		assertEquals(5, scoping.getProxyCount().intValue());
	}

	@Test
	public void resolveAuthnRequestWithEmptyScoping() throws IOException {
		Saml2Scoping scoping =
			parseSaml2Scoping("authn_request_with_empty_scoping.xml");

		List<String> idpList = scoping.getIdpList();
		assertEquals(0, idpList.size());

		List<String> requesterIds = scoping.getRequesterIds();
		assertEquals(0, requesterIds.size());

		assertNull(scoping.getProxyCount());
	}

	@Test
	public void resolveAuthnRequestWithNoScoping() throws IOException {
		Saml2Scoping scoping =
			parseSaml2Scoping("authn_request_with_no_scoping.xml");

		assertNull(scoping);
	}

	private Saml2Scoping parseSaml2Scoping(String fileName) throws IOException {
		byte[] xml = StreamUtils.copyToByteArray(
			new ClassPathResource(String.format("authn_requests/%s", fileName)).getInputStream());
		return ((Saml2AuthenticationRequest)
			subject.resolve(xml, Collections.emptyList(), Collections.emptyList())).getScoping();

	}

	private Saml2Endpoint saml2Endpoint(String location) {
		Saml2Endpoint saml2Endpoint = new Saml2Endpoint();
		saml2Endpoint.setLocation(location);
		return saml2Endpoint;
	}
}
