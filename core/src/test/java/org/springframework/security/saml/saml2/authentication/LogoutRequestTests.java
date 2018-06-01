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

package org.springframework.security.saml.saml2.authentication;

import java.time.Clock;
import java.util.Arrays;

import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.saml.saml2.metadata.NameId.EMAIL;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA256;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA512;
import static org.springframework.security.saml.spi.ExamplePemKey.RSA_TEST_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.SP_RSA_KEY;
import static org.springframework.security.saml.util.DateUtils.toZuluTime;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml.util.XmlTestUtil.getNodes;

class LogoutRequestTests {

	SpringSecuritySaml saml = new OpenSamlImplementation(Clock.systemUTC()).init();
	private String issuer = "http://sp.test.org";
	private DateTime instant = new DateTime();
	private String destination = "http://idp.test.org";

	@Test
	public void fromXml() {
		LogoutRequest request = (LogoutRequest) saml.resolve(EXAMPLE, Arrays.asList(RSA_TEST_KEY.getSimpleKey("test")), null);
		assertThat(request.getId(), equalTo("request-id"));
		assertNotNull(request.getDestination(), equalTo("request-id"));
		assertThat(request.getDestination(), equalTo("request-id"));
	}

	@Test
	public void toXml() {

		LogoutRequest request = new LogoutRequest()
			.setId("request-id")
			.setDestination(new Endpoint().setLocation(destination))
			.setSigningKey(RSA_TEST_KEY.getSimpleKey("test"), RSA_SHA256, SHA512)
			.setNameId(new NameIdPrincipal()
				.setNameQualifier(issuer)
				.setSpNameQualifier(issuer)
				.setFormat(EMAIL)
				.setValue("test@test.org")
			)
			.setReason(LogoutReason.USER)
			.setIssueInstant(instant)
			.setNotOnOrAfter(instant.plusHours(1))
			.setIssuer(new Issuer().setValue(issuer));
		String xml = saml.toXml(request);

		assertNodeCount(xml, "//samlp:LogoutRequest", 1);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest").iterator().next(), "Destination", equalTo(destination));
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest").iterator().next(), "ID", equalTo("request-id"));
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest").iterator().next(), "Version", equalTo("2.0"));

		//OpenSAML doesn't write out issuer
//		assertNodeCount(xml, "//samlp:Issuer", 1);
//		assertThat(getNodes(xml, "//samlp:Issuer").iterator().next().getTextContent(), equalTo(issuer));

		assertNodeCount(xml, "//ds:Signature", 1);

		assertNodeCount(xml, "//ds:DigestMethod", 1);
		assertNodeAttribute(
			getNodes(xml, "//ds:DigestMethod").iterator().next(), "Algorithm", equalTo(SHA512.toString()));

		assertNodeCount(xml, "//ds:SignatureMethod", 1);
		assertNodeAttribute(
			getNodes(xml, "//ds:SignatureMethod").iterator().next(), "Algorithm", equalTo(RSA_SHA256.toString()));

		assertNodeCount(xml, "//samlp:LogoutRequest/saml:NameID", 1);
		assertNodeAttribute(getNodes(xml, "//samlp:LogoutRequest/saml:NameID").iterator().next(), "NameQualifier", equalTo(issuer));
		assertNodeAttribute(getNodes(xml, "//samlp:LogoutRequest/saml:NameID").iterator().next(), "SPNameQualifier", equalTo(issuer));
		assertNodeAttribute(getNodes(xml, "//samlp:LogoutRequest/saml:NameID").iterator().next(), "Format", equalTo(EMAIL.toString()));

		saml.validateSignature(saml.resolve(xml, null, null), Arrays.asList(RSA_TEST_KEY.getSimpleKey("test")));

		Exception expected =
			assertThrows(
				SignatureException.class,
				//using the wrong key
				() -> saml.validateSignature(saml.resolve(xml, null, null), Arrays.asList(SP_RSA_KEY.getSimpleKey("wrong")))
			);
		assertThat(expected.getMessage(), equalTo("Signature validation against a  object failed using 1 key."));

	}

	private String EXAMPLE  = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
		"xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"request-id\" " +
		"Version=\"2.0\" IssueInstant=\""+toZuluTime(instant)+"\" Destination=\"http://idp.example" +
		".com/SingleLogoutService.php\">\n" +
		"  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>\n" +
		"  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"    <ds:SignedInfo>\n" +
		"      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
		"      <ds:Reference URI=\"#request-id\">\n" +
		"        <ds:Transforms>\n" +
		"          <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
		"          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"        </ds:Transforms>\n" +
		"        <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
		"        <ds:DigestValue>dig-value</ds:DigestValue>\n" +
		"      </ds:Reference>\n" +
		"    </ds:SignedInfo>\n" +
		"    <ds:SignatureValue>sig-value</ds:SignatureValue>\n" +
		"    <ds:KeyInfo>\n" +
		"      <ds:X509Data>\n" +
		"        <ds:X509Certificate>certificate value</ds:X509Certificate>\n" +
		"      </ds:X509Data>\n" +
		"    </ds:KeyInfo>\n" +
		"  </ds:Signature>\n" +
		"  <saml:NameID SPNameQualifier=\""+issuer+"\" " +
		"Format=\"" + NameId.EMAIL.toString() +
		"\">test@test.org</saml:NameID>\n" +
		"</samlp:LogoutRequest>";
}