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

import java.io.IOException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.model.attribute.Saml2Attribute;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationContext;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationStatement;
import org.springframework.security.saml2.model.authentication.Saml2Conditions;
import org.springframework.security.saml2.model.authentication.Saml2Issuer;
import org.springframework.security.saml2.model.authentication.Saml2NameIdPrincipal;
import org.springframework.security.saml2.model.authentication.Saml2Response;
import org.springframework.security.saml2.model.authentication.Saml2Scoping;
import org.springframework.security.saml2.model.authentication.Saml2Subject;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmation;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationData;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationMethod;
import org.springframework.security.saml2.model.metadata.Saml2Binding;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.model.metadata.Saml2NameId;
import org.springframework.util.StreamUtils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.saml2.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml2.util.XmlTestUtil.getNodes;

class OpenSaml2ImplementationTest {

	private OpenSaml2Implementation subject = new OpenSaml2Implementation(Clock.systemDefaultZone());

	@BeforeEach
	public void setup() {
		subject.bootstrap();
	}

	@Test
	void authenticationRequestWithScopingToXml() {
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
	void resolveAuthnRequestWithScoping() throws IOException {
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
	void resolveAuthnRequestWithEmptyScoping() throws IOException {
		Saml2Scoping scoping =
			parseSaml2Scoping("authn_request_with_empty_scoping.xml");

		List<String> idpList = scoping.getIdpList();
		assertEquals(0, idpList.size());

		List<String> requesterIds = scoping.getRequesterIds();
		assertEquals(0, requesterIds.size());

		assertNull(scoping.getProxyCount());
	}

	@Test
	void resolveAuthnRequestWithNoScoping() throws IOException {
		Saml2Scoping scoping =
			parseSaml2Scoping("authn_request_with_no_scoping.xml");

		assertNull(scoping);
	}

	@Test
	void resolveAuthnResponseWithComplexAttributeValue() throws IOException {
		byte[] xml = StreamUtils.copyToByteArray(
			new ClassPathResource("authn_response/authn_response_with_xml_element_attribute_value.xml").getInputStream());
		Saml2Response response = (Saml2Response) subject.resolve(xml, Collections.emptyList(), Collections.emptyList());
		Saml2Assertion assertion = response.getAssertions().get(0);
		Saml2Attribute attribute = assertion.getFirstAttribute("urn:mace:dir:attribute-def:eduPersonTargetedID");

		List<Object> values = attribute.getValues();
		assertEquals(1, values.size());

		String value = (String) values.get(0);
		assertEquals("urn:collab:person:example.com:admin", value);
	}

	@Test
	public void assertionWithAuthenticatingAuthoritiesToXml() {
		String authenticatingAuthority = "http://authenticating_authority";
		Saml2Assertion assertion = new Saml2Assertion()
			.setIssuer(new Saml2Issuer())
			.setSubject(new Saml2Subject()
				.setPrincipal(new Saml2NameIdPrincipal().setValue("admin").setFormat(Saml2NameId.UNSPECIFIED))
				.setConfirmations(Arrays.asList(
					new Saml2SubjectConfirmation()
						.setMethod(Saml2SubjectConfirmationMethod.BEARER)
						.setConfirmationData(new Saml2SubjectConfirmationData().setInResponseTo("inResponseTo")))))
			.setAuthenticationStatements(Arrays.asList(
				new Saml2AuthenticationStatement()
					.setAuthenticationContext(new Saml2AuthenticationContext()
						.setAuthenticatingAuthorities(Arrays.asList(authenticatingAuthority)))))
			.setConditions(new Saml2Conditions());

		String xml = subject.toXml(assertion);

		Iterable<Node> nodes = getNodes(xml, "//saml2:AuthenticatingAuthority");
		String textContent = nodes.iterator().next().getTextContent();
		assertEquals(authenticatingAuthority, textContent);
	}

	@Test
	public void resolveAssertionWithAuthenticatinAuthorities() throws IOException {
		Saml2AuthenticationContext authenticationContext =
			parseAuthenticationContext("assertion_with_authenticating_authority.xml");
		assertEquals(2, authenticationContext.getAuthenticatingAuthorities().size());
		assertEquals("http://authenticating_authority", authenticationContext.getAuthenticatingAuthorities().get(0));
	}

	private Saml2AuthenticationContext parseAuthenticationContext(String fileName) throws IOException {
		byte[] xml = StreamUtils.copyToByteArray(
			new ClassPathResource(String.format("assertions/%s", fileName)).getInputStream());
		return ((Saml2Assertion)
			subject.resolve(xml, Collections.emptyList(), Collections.emptyList()))
			.getAuthenticationStatements().get(0)
			.getAuthenticationContext();
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
