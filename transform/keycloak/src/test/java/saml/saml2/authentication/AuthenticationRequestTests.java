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
package saml.saml2.authentication;

import java.util.Collections;

import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.RequestedAuthenticationContext;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Node;
import saml.saml2.metadata.MetadataBase;

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
		assertNodeAttribute(nodes.iterator().next(), "Format", equalTo(NameId.PERSISTENT.toString()));

		assertNodeCount(xml, "//samlp:RequestedAuthnContext", 0);

		assertNodeCount(xml, "//ds:Signature", 1);
		nodes = assertNodeCount(xml, "//ds:Signature/ds:SignedInfo/ds:SignatureMethod", 1);
		assertNodeAttribute(nodes.iterator().next(), "Algorithm", AlgorithmMethod.RSA_SHA1.toString());

		nodes = assertNodeCount(xml, "//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod", 1);
		assertNodeAttribute(nodes.iterator().next(), "Algorithm", DigestMethod.SHA1.toString());
	}

	@Test
	public void parseOpenSamlGenerated() {

		String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<saml2p:AuthnRequest AssertionConsumerServiceURL=\"http://sp.localhost:8080/uaa/saml/sp/SSO/alias/sp-alias\" Destination=\"http://idp.localhost:8080/uaa/saml/idp/SSO/alias/idp-alias\" ForceAuthn=\"false\" ID=\"7f24b8b7-2729-4395-8d6d-15d589b1d212\" IsPassive=\"false\" IssueInstant=\"2018-11-08T17:42:21.195Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://sp.localhost:8080/uaa</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"<ds:SignedInfo>\n" +
			"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
			"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
			"<ds:Reference URI=\"#7f24b8b7-2729-4395-8d6d-15d589b1d212\">\n" +
			"<ds:Transforms>\n" +
			"<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
			"<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
			"</ds:Transforms>\n" +
			"<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
			"<ds:DigestValue>arEsOu92QLpsjSVkO1OE7bqfhfM=</ds:DigestValue>\n" +
			"</ds:Reference>\n" +
			"</ds:SignedInfo>\n" +
			"<ds:SignatureValue>\n" +
			"TKKoxYu85FAJG24mGkFsrNIszIz2bLajfyqC3wVnSEbtQOV6JPlFgv2SIcTKu56AnXaWHPoWbVAI\n" +
			"4es/xfzgmwpM57HGReFZ8eIeNf1/6TfGT61JuAh6ITeE6lOJLLusNzAXD/dSYdj3Qrv2p8DOREuJ\n" +
			"zJSZSu8IhGXWnqPlpVs=\n" +
			"</ds:SignatureValue>\n" +
			"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICgTCCAeoCCQDtqkmhbmvARzANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMCVVMxEzARBgNV\n" +
			"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
			"aXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQDDBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAe\n" +
			"Fw0xODA0MzAyMTA1MTNaFw0yODA0MjcyMTA1MTNaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwK\n" +
			"V2FzaGluZ3RvbjESMBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkg\n" +
			"U0FNTDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1sMIGfMA0G\n" +
			"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBRIHAaQLxTLJQDt8NDz/zT1PZuwu9pwo44zGLnrbU22qX\n" +
			"LuNhbur/nqxEpIJBjy1BYyeGvlcGhOXTu1uThZdmKC71KwGNgTHdE1ciC/Fu/GMtgoVsQujtOV92\n" +
			"Fw5mMcJR7yNIsGP0+4nCWj41M+4h/EdbUawCWNWEqrgyvDrGWwIDAQABMA0GCSqGSIb3DQEBCwUA\n" +
			"A4GBALcvf1p3lOPlgcJNv2JUh1Z53VWbOOPRqm31AXCN5rvb52nqGi5gz1jJz1oXliBRsvOt5cDP\n" +
			"89uUTAQ2HWuJTlm0M/1dJh1CJ7cjugoFEMYCjEA72CS8wYjujtZhXZYFdI/eMeJw0IoRqVh3mZqU\n" +
			"4V1B7udBKD/Kmbwpm4XZI/An</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"/></saml2p:AuthnRequest>";

		config.fromXml(xml, Collections.singletonList(idpVerifying), null);
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
		assertNodeAttribute(nodes.iterator().next(), "Format", equalTo(NameId.PERSISTENT.toString()));

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
