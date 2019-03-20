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
package org.springframework.security.saml.saml2.authentication;

import java.util.Collections;

import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.MetadataBase;

import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.NameID;
import org.w3c.dom.Node;

import static java.lang.Boolean.FALSE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.saml2.metadata.NameId.PERSISTENT;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml.util.XmlTestUtil.assertTextNodeValue;
import static org.springframework.security.saml.util.XmlTestUtil.getNodes;

class AuthenticationRequestTests extends MetadataBase {

	@Test
	public void createWithDefaults() {

		AuthenticationRequest request = helper.authenticationRequest(serviceProviderMetadata, identityProviderMetadata);
		String xml = config.toXml(request);

		assertNodeCount(xml, "//samlp:AuthnRequest", 1);
		Iterable<Node> nodes = getNodes(xml, "//samlp:AuthnRequest");
		assertNodeAttribute(nodes.iterator().next(), "Version", equalTo("2.0"));
		assertNodeAttribute(nodes.iterator().next(), "IssueInstant", notNullValue(String.class));
		assertNodeAttribute(nodes.iterator().next(), "ForceAuthn", equalTo("false"));
		assertNodeAttribute(nodes.iterator().next(), "IsPassive", equalTo("false"));
		assertNodeAttribute(
			nodes.iterator().next(),
			"ProtocolBinding",
			equalTo("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
		);
		assertNodeAttribute(
			nodes.iterator().next(),
			"AssertionConsumerServiceURL",
			equalTo("http://sp.localhost:8080/uaa/saml/sp/SSO/alias/sp-alias")
		);
		assertNodeAttribute(
			nodes.iterator().next(),
			"Destination",
			equalTo("http://idp.localhost:8080/uaa/saml/idp/SSO/alias/idp-alias")
		);

		assertNodeCount(xml, "//samlp:NameIDPolicy", 1);
		nodes = getNodes(xml, "//samlp:NameIDPolicy");
		assertNodeAttribute(nodes.iterator().next(), "Format", equalTo(NameID.PERSISTENT));

		assertNodeCount(xml, "//samlp:RequestedAuthnContext", 0);
	}

	@Test
	public void parseWithDefaults() {
		AuthenticationRequest request = helper.authenticationRequest(serviceProviderMetadata, identityProviderMetadata);
		String xml = config.toXml(request);
		AuthenticationRequest data =
			(AuthenticationRequest) config.fromXml(xml, Collections.singletonList(idpVerifying), null);
		assertNotNull(data);
		assertNotNull(data.getImplementation());
		assertNotNull(data.getSignature());
		assertTrue(data.getSignature().isValidated());


		assertSame(Binding.POST, data.getBinding());
		assertEquals(
			"http://sp.localhost:8080/uaa/saml/sp/SSO/alias/sp-alias",
			data.getAssertionConsumerService().getLocation()
		);
		assertSame(PERSISTENT, data.getNameIdPolicy().getFormat());

		assertThat(data.getVersion(), equalTo("2.0"));
		assertThat(data.getIssueInstant(), notNullValue(DateTime.class));
		assertThat(data.isForceAuth(), equalTo(FALSE));
		assertThat(data.isPassive(), equalTo(FALSE));
		assertThat(data.getBinding().toString(), equalTo("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
		assertThat(
			data.getAssertionConsumerService().getLocation(),
			equalTo("http://sp.localhost:8080/uaa/saml/sp/SSO/alias/sp-alias")
		);
	}

	@Test
	public void createWithAutContext() {

		AuthenticationRequest request = helper.authenticationRequest(serviceProviderMetadata, identityProviderMetadata);
		request.setRequestedAuthenticationContext(RequestedAuthenticationContext.exact);
		request.setAuthenticationContextClassReference(AuthenticationContextClassReference.PASSWORD_PROTECTED_TRANSPORT);

		String xml = config.toXml(request);

		assertNodeCount(xml, "//samlp:AuthnRequest", 1);
		Iterable<Node> nodes = getNodes(xml, "//samlp:AuthnRequest");
		assertNodeAttribute(nodes.iterator().next(), "Version", equalTo("2.0"));
		assertNodeAttribute(nodes.iterator().next(), "IssueInstant", notNullValue(String.class));
		assertNodeAttribute(nodes.iterator().next(), "ForceAuthn", equalTo("false"));
		assertNodeAttribute(nodes.iterator().next(), "IsPassive", equalTo("false"));
		assertNodeAttribute(
			nodes.iterator().next(),
			"ProtocolBinding",
			equalTo("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
		);
		assertNodeAttribute(
			nodes.iterator().next(),
			"AssertionConsumerServiceURL",
			equalTo("http://sp.localhost:8080/uaa/saml/sp/SSO/alias/sp-alias")
		);
		assertNodeAttribute(
			nodes.iterator().next(),
			"Destination",
			equalTo("http://idp.localhost:8080/uaa/saml/idp/SSO/alias/idp-alias")
		);

		assertNodeCount(xml, "//samlp:NameIDPolicy", 1);
		nodes = getNodes(xml, "//samlp:NameIDPolicy");
		assertNodeAttribute(nodes.iterator().next(), "Format", equalTo(NameID.PERSISTENT));

		assertNodeCount(xml, "//samlp:RequestedAuthnContext", 1);
		nodes = getNodes(xml, "//samlp:RequestedAuthnContext");
		assertNodeAttribute(nodes.iterator().next(), "Comparison", equalTo("exact"));

		// AuthnContextClassRef must be direct child of RequestedAuthnContext
		assertNodeCount(xml, "//samlp:RequestedAuthnContext/saml:AuthnContextClassRef", 1);
		assertNodeCount(xml, "//samlp:RequestedAuthnContext/saml:AuthnContextClassRef/text()", 1);
		nodes = getNodes(xml, "//samlp:RequestedAuthnContext/saml:AuthnContextClassRef/text()");
		assertTextNodeValue(
			nodes.iterator().next(),
			equalTo("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
		);
	}

	@Test
	public void parseWithAutContext() {
		AuthenticationRequest request = helper.authenticationRequest(serviceProviderMetadata, identityProviderMetadata);
		request.setRequestedAuthenticationContext(RequestedAuthenticationContext.exact);
		request.setAuthenticationContextClassReference(AuthenticationContextClassReference.PASSWORD_PROTECTED_TRANSPORT);

		String xml = config.toXml(request);
		AuthenticationRequest data =
			(AuthenticationRequest) config.fromXml(xml, Collections.singletonList(idpVerifying), null);
		assertNotNull(data);
		assertNotNull(data.getImplementation());
		assertNotNull(data.getSignature());
		assertTrue(data.getSignature().isValidated());


		assertSame(Binding.POST, data.getBinding());
		assertEquals(
			"http://sp.localhost:8080/uaa/saml/sp/SSO/alias/sp-alias",
			data.getAssertionConsumerService().getLocation()
		);
		assertSame(PERSISTENT, data.getNameIdPolicy().getFormat());
		assertSame(RequestedAuthenticationContext.exact, data.getRequestedAuthenticationContext());
		assertSame(
			AuthenticationContextClassReference.PASSWORD_PROTECTED_TRANSPORT,
			data.getAuthenticationContextClassReference()
		);

		assertThat(data.getVersion(), equalTo("2.0"));
		assertThat(data.getIssueInstant(), notNullValue(DateTime.class));
		assertThat(data.isForceAuth(), equalTo(FALSE));
		assertThat(data.isPassive(), equalTo(FALSE));
		assertThat(data.getBinding().toString(), equalTo("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
		assertThat(
			data.getAssertionConsumerService().getLocation(),
			equalTo("http://sp.localhost:8080/uaa/saml/sp/SSO/alias/sp-alias")
		);
	}

}
