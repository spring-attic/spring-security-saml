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

import java.time.Clock;
import java.util.Arrays;

import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.CanonicalizationMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.saml2.signature.SignatureException;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.saml2.metadata.NameId.EMAIL;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA256;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA512;
import static org.springframework.security.saml.saml2.signature.CanonicalizationMethod.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA256;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA512;
import static org.springframework.security.saml.spi.ExamplePemKey.RSA_TEST_KEY;
import static org.springframework.security.saml.spi.ExamplePemKey.SP_RSA_KEY;
import static org.springframework.security.saml.util.DateUtils.fromZuluTime;
import static org.springframework.security.saml.util.DateUtils.toZuluTime;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeAttribute;
import static org.springframework.security.saml.util.XmlTestUtil.assertNodeCount;
import static org.springframework.security.saml.util.XmlTestUtil.getNodes;

class LogoutObjectTests {

	SpringSecuritySaml saml = new OpenSamlImplementation(Clock.systemUTC()).init();
	private String issuer = "http://sp.test.org";
	private DateTime instant = new DateTime();
	private String destination = "http://idp.test.org";
	private String EXAMPLE_REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<saml2p:LogoutRequest Destination=\"http://idp.test.org\" ID=\"request-id\" " +
		"IssueInstant=\"2018-06-04T14:53:16.712Z\" NotOnOrAfter=\"2018-06-04T15:53:16.712Z\" Version=\"2.0\" " +
		"xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer " +
		"xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://sp.test.org</saml2:Issuer><ds:Signature " +
		"xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"<ds:SignedInfo>\n" +
		"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
		"<ds:Reference URI=\"#request-id\">\n" +
		"<ds:Transforms>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"</ds:Transforms>\n" +
		"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>\n" +
		"<ds:DigestValue>zEvGcnSA/2RwlBDayoKKmLIt/QfpBZc/76ticiNNvP2ldbnXZ9ibNcyoWbeioBhh9L4eMxWCjJFC\n" +
		"BrVXibxQTg==</ds:DigestValue>\n" +
		"</ds:Reference>\n" +
		"</ds:SignedInfo>\n" +
		"<ds:SignatureValue>\n" +
		"Vmlrlk45qBbrDLRsMNWXgdTp1XLNutnrag7PW6BEGoG9LcQccnwOBCxsIdbbHWJL5RbuG80C4C2j\n" +
		"FKMOAzu8sGmiw2InNLAWamaOs4tzrzWgmkud93oJL5DFdC8jjCZz6USUcoKvr1dNprSV45s4wFwC\n" +
		"MkAYpfhh2JsL7m094Po=\n" +
		"</ds:SignatureValue>\n" +
		"<ds:KeyInfo><ds:X509Data><ds:X509Certificate" +
		">MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
		"YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
		"BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
		"MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
		"ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
		"HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
		"gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
		"4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
		"xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
		"GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
		"MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
		"EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
		"MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
		"2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
		"ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds" +
		":KeyInfo></ds:Signature><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" " +
		"NameQualifier=\"http://sp.test.org\" SPNameQualifier=\"http://sp.test.org\" " +
		"xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">test@test.org</saml2:NameID></saml2p:LogoutRequest>";
	private String EXAMPLE_RESPONSE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<saml2p:LogoutResponse Destination=\"http://idp.test.org\" ID=\"response-id\" InResponseTo=\"in-response-to\"" +
		" IssueInstant=\"2018-06-04T19:24:09.572Z\" Version=\"2.0\" " +
		"xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer NameQualifier=\"name qualifier\" " +
		"SPNameQualifier=\"sp name qualifier\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://sp.test" +
		".org</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"<ds:SignedInfo>\n" +
		"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\"/>\n" +
		"<ds:Reference URI=\"#response-id\">\n" +
		"<ds:Transforms>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"</ds:Transforms>\n" +
		"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
		"<ds:DigestValue>qemZnU8Q1s8jNPhYl37mO8FToJnpU/k7V4BwnryApVA=</ds:DigestValue>\n" +
		"</ds:Reference>\n" +
		"</ds:SignedInfo>\n" +
		"<ds:SignatureValue>\n" +
		"teqIAaYeNrUqEOOCr7a1G7gWLU5e+F+WpV7J1EVtxCRXIZde0O1p56nQ8gZaHmYjvPdMuXuf2uo5\n" +
		"XwAHjvaINoqRhotR3cY5xi/jgYQvz8VXTJc1OAEe5fCOiAIbsapNaW/0vhWDdq4F1I0GGEnztHNj\n" +
		"w95+YBobRHd6CKQCCzw=\n" +
		"</ds:SignatureValue>\n" +
		"<ds:KeyInfo><ds:X509Data><ds:X509Certificate" +
		">MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
		"YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
		"BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
		"MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
		"ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
		"HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
		"gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
		"4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
		"xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
		"GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
		"MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
		"EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
		"MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
		"2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
		"ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds" +
		":KeyInfo></ds:Signature><saml2p:Status><saml2p:StatusCode " +
		"Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/><saml2p:StatusMessage>User logged " +
		"out!</saml2p:StatusMessage></saml2p:Status></saml2p:LogoutResponse>";

	@Test
	public void requestFromXml() {
		LogoutRequest request = (LogoutRequest) saml.resolve(
			EXAMPLE_REQUEST, Arrays.asList(RSA_TEST_KEY.getSimpleKey("test")), null);
		assertThat(request.getId(), equalTo("request-id"));
		assertNotNull(request.getDestination());
		assertThat(request.getDestination().getLocation(), equalTo("http://idp.test.org"));
		assertThat(request.getIssueInstant(), equalTo(fromZuluTime("2018-06-04T14:53:16.712Z")));
		assertNotNull(request.getIssuer());
		assertThat(request.getIssuer().getValue(), equalTo("http://sp.test.org"));
		assertNotNull(request.getSignature());
		assertTrue(request.getSignature().isValidated());
		//OpenSAML doesn't set this value
		//assertThat(request.getSignature().getDigestAlgorithm(), equalTo(SHA512));
		assertThat(request.getSignature().getCanonicalizationAlgorithm(), equalTo(ALGO_ID_C14N_EXCL_OMIT_COMMENTS));
		assertThat(request.getSignature().getSignatureAlgorithm(), equalTo(RSA_SHA256));

		NameIdPrincipal nameId = request.getNameId();
		assertNotNull(nameId);
		assertThat(nameId.getFormat(), equalTo(EMAIL));
		assertThat(nameId.getNameQualifier(), equalTo("http://sp.test.org"));
		assertThat(nameId.getSpNameQualifier(), equalTo("http://sp.test.org"));
		assertThat(nameId.getValue(), equalTo("test@test.org"));
	}

	@Test
	public void requestToXml() {

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
			getNodes(xml, "//samlp:LogoutRequest").iterator().next(),
			"Destination",
			equalTo(destination)
		);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest").iterator().next(),
			"ID",
			equalTo("request-id")
		);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest").iterator().next(),
			"Version",
			equalTo("2.0")
		);

		//OpenSAML doesn't write out issuer
		assertNodeCount(xml, "//saml:Issuer", 1);
		assertThat(getNodes(xml, "//saml:Issuer").iterator().next().getTextContent(), equalTo(issuer));

		assertNodeCount(xml, "//ds:Signature", 1);

		assertNodeCount(xml, "//ds:DigestMethod", 1);
		assertNodeAttribute(
			getNodes(xml, "//ds:DigestMethod").iterator().next(),
			"Algorithm",
			equalTo(SHA512.toString())
		);

		assertNodeCount(xml, "//ds:SignatureMethod", 1);
		assertNodeAttribute(
			getNodes(xml, "//ds:SignatureMethod").iterator().next(),
			"Algorithm",
			equalTo(RSA_SHA256.toString())
		);

		assertNodeCount(xml, "//samlp:LogoutRequest/saml:NameID", 1);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest/saml:NameID").iterator().next(), "NameQualifier", equalTo(issuer));
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest/saml:NameID").iterator().next(), "SPNameQualifier", equalTo(issuer));
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutRequest/saml:NameID").iterator().next(), "Format", equalTo(EMAIL.toString()));

		saml.validateSignature(saml.resolve(xml, null, null), Arrays.asList(RSA_TEST_KEY.getSimpleKey("test")));

		Exception expected =
			assertThrows(
				SignatureException.class,
				//using the wrong key
				() -> saml.validateSignature(
					saml.resolve(xml, null, null), Arrays.asList(SP_RSA_KEY.getSimpleKey("wrong")))
			);
		assertThat(
			expected.getMessage(), equalTo(
				"Signature validation against a org.opensaml.saml.saml2.core.impl.LogoutRequestImpl object failed " +
					"using 1 key."));

	}

	@Test
	public void responseFromXml() throws Exception {
		LogoutResponse response = (LogoutResponse) saml.resolve(
			EXAMPLE_RESPONSE,
			Arrays.asList(RSA_TEST_KEY.getSimpleKey("test")),
			null
		);
		assertThat(response.getId(), equalTo("response-id"));
		assertNotNull(response.getDestination());
		assertThat(response.getDestination(), equalTo(destination));
		assertThat(response.getIssueInstant(), equalTo(fromZuluTime("2018-06-04T19:24:09.572Z")));
		assertThat(response.getInResponseTo(), equalTo("in-response-to"));
		assertThat(response.getIssuer().getValue(), equalTo(issuer));
		assertThat(response.getStatus().getCode(), equalTo(StatusCode.SUCCESS));
		assertThat(response.getStatus().getMessage(), equalTo("User logged out!"));

		Signature signature = saml.validateSignature(response, Arrays.asList(RSA_TEST_KEY.getSimpleKey("test")));
		assertNotNull(signature);
		assertThat(signature.isValidated(), equalTo(true));
		assertThat(signature.getSignatureAlgorithm(), equalTo(AlgorithmMethod.RSA_SHA512));
		assertThat(signature.getDigestAlgorithm(), equalTo(DigestMethod.SHA256));
		assertThat(
			signature.getCanonicalizationAlgorithm(),
			equalTo(CanonicalizationMethod.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
		);
	}

	@Test
	public void responseToXml() throws Exception {
		LogoutResponse response = new LogoutResponse()
			.setInResponseTo("in-response-to")
			.setDestination(destination)
			.setId("response-id")
			.setIssueInstant(instant)
			.setIssuer(
				new Issuer()
					.setValue(issuer)
					.setNameQualifier("name qualifier")
					.setSpNameQualifier("sp name qualifier")
			)
			.setStatus(new Status()
				.setCode(StatusCode.SUCCESS)
				.setMessage("User logged out!")
				.setDetail("User logged out details")
			)
			.setVersion("2.0")
			.setSigningKey(
				RSA_TEST_KEY.getSimpleKey("test"),
				RSA_SHA512,
				DigestMethod.SHA256
			)
			.setConsent("consent");

		String xml = saml.toXml(response);

		assertNodeCount(xml, "//samlp:LogoutResponse", 1);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutResponse").iterator().next(),
			"Destination",
			equalTo(destination)
		);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutResponse").iterator().next(),
			"ID",
			equalTo("response-id")
		);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutResponse").iterator().next(),
			"Version",
			equalTo("2.0")
		);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutResponse").iterator().next(),
			"IssueInstant",
			equalTo(toZuluTime(instant))
		);


		//OpenSAML doesn't write out issuer
		assertNodeCount(xml, "//saml:Issuer", 1);
		assertThat(getNodes(xml, "//saml:Issuer").iterator().next().getTextContent(), equalTo(issuer));

		assertNodeCount(xml, "//ds:Signature", 1);

		assertNodeCount(xml, "//ds:DigestMethod", 1);
		assertNodeAttribute(
			getNodes(xml, "//ds:DigestMethod").iterator().next(),
			"Algorithm",
			equalTo(SHA256.toString())
		);

		assertNodeCount(xml, "//ds:SignatureMethod", 1);
		assertNodeAttribute(
			getNodes(xml, "//ds:SignatureMethod").iterator().next(),
			"Algorithm",
			equalTo(RSA_SHA512.toString())
		);

		assertNodeCount(xml, "//samlp:LogoutResponse/samlp:Status", 1);
		assertNodeCount(xml, "//samlp:LogoutResponse/samlp:Status/samlp:StatusCode", 1);
		assertNodeCount(xml, "//samlp:LogoutResponse/samlp:Status/samlp:StatusMessage", 1);
		assertNodeAttribute(
			getNodes(xml, "//samlp:LogoutResponse/samlp:Status/samlp:StatusCode").iterator().next(),
			"Value",
			equalTo(StatusCode.SUCCESS.toString())
		);
		assertThat(
			getNodes(xml, "//samlp:LogoutResponse/samlp:Status/samlp:StatusMessage").iterator().next().getTextContent(),
			equalTo("User logged out!")
		);

		saml.validateSignature(saml.resolve(xml, null, null), Arrays.asList(RSA_TEST_KEY.getSimpleKey("test")));

		Exception expected =
			assertThrows(
				SignatureException.class,
				//using the wrong key
				() -> saml.validateSignature(
					saml.resolve(xml, null, null), Arrays.asList(SP_RSA_KEY.getSimpleKey("wrong")))
			);
		assertThat(
			expected.getMessage(), equalTo(
				"Signature validation against a org.opensaml.saml.saml2.core.impl.LogoutResponseImpl object failed " +
					"using 1 key."));


	}
}