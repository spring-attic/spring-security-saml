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
package org.springframework.security.samples;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class MetadataTrustCheckBootTest {

	@Autowired
	private MockMvc mockMvc;

	private String spBaseUrl;

	@Autowired
	@Qualifier("spSamlServerConfiguration")
	private SamlServerConfiguration config;

	@Autowired(required = false)
	@Qualifier("samlServiceProviderProvisioning")
	SamlProviderProvisioning<ServiceProviderService> samlProvisioning;

	private List<ExternalIdentityProviderConfiguration> providers;
	private ExternalIdentityProviderConfiguration trustCheckProvider;

	@BeforeEach
	void setUp() {
		providers = config.getServiceProvider().getProviders();
		List<ExternalIdentityProviderConfiguration> newConfig = new ArrayList<>(providers);
		trustCheckProvider = new ExternalIdentityProviderConfiguration()
			.setAlias("dual")
			.setMetadata(METADATA_TRUST_CHECK)
			.setSkipSslValidation(true)
			.setMetadataTrustCheck(true)
			.setVerificationKeys(asList(METADATA_TRUST_CHECK_KEY))
			.setLinktext("Metadata Trust Check IDP/SP Metadata");
		newConfig.add(trustCheckProvider);
		config.getServiceProvider().setProviders(newConfig);

		spBaseUrl = "http://localhost";
		config.getServiceProvider().setBasePath(spBaseUrl);
	}

	@AfterEach
	public void reset() {
		config.getServiceProvider().setSingleLogoutEnabled(true);
		config.getServiceProvider().setProviders(providers);
	}

	@Test
	public void metadataTrustCheckWorks() throws Exception {
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(containsString("Metadata Trust Check IDP/SP Metadata")))
			.andReturn();
	}

	@Test
	public void metadataTrustCheckFails() throws Exception {
		trustCheckProvider.setVerificationKeys(asList(SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData().getCertificate()));
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(not(containsString("Metadata Trust Check IDP/SP Metadata"))))
			.andReturn();
	}

	@Test
	public void staticKeysAreAdded() throws Exception {
		trustCheckProvider
			.setVerificationKeys(asList(SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData().getCertificate()))
			.setMetadataTrustCheck(false);
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(containsString("Metadata Trust Check IDP/SP Metadata")))
			.andReturn();

		IdentityProviderMetadata provider =
			samlProvisioning.getHostedProvider().getRemoteProvider("login.run.pivotal.io");
		List<SimpleKey> keys = provider.getIdentityProvider().getKeys();
		assertTrue(hasKey(keys, SimpleSamlPhpTestKeys.getSimpleSamlPhpKeyData().getCertificate()));
		assertTrue(hasKey(keys, METADATA_TRUST_CHECK_KEY));
	}

	private boolean hasKey(List<SimpleKey> keys, String certificate) {
		return keys
			.stream()
			.anyMatch(k -> certificate.equals(k.getCertificate()));
	}

	private static String METADATA_TRUST_CHECK = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"login.run.pivotal.io\" entityID=\"login.run.pivotal.io\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#login.run.pivotal.io\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>cayGaIpGtYkEXMr0g+scVayzxMI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>EPu6XnPsdMNNY4fuQczAdGB8029i/t+7tZ2w6xaX1WzutRji76PL2e6zfiZvcBGRrcPYmqVJZC6BorBcvMCIVxE+MxKWp4JE9qsQUMoXGpovbBmiKzMfqaO+lcusCmX6CRyqni6P75L1Sff2j31Sp/QxgXkA3ZHvrcaNynMCWdYaqFUuk/L44CI3FllceGlmWDNEM7gPIEYAlQ6A0ct7y5+Dj+aZxDofS8bTCR3dgf4fw6+gu2Cxf+zbSflQ2kT4jTW0GBsOJ6NBZZCP5f7+WCTWD4YFGSbCk/KisM/FS7i7seedoTJplYLyn+2YYUO1xKnFF8wNL5Uqi92lC1hgGw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
		"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
		"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
		"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
		"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
		"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
		"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
		"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
		"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
		"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
		"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
		"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
		"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
		"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
		"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
		"kKe5nrXyHOORz+ttXkYkp5uEBhpZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
		"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
		"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
		"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
		"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
		"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
		"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
		"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
		"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
		"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
		"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
		"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
		"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
		"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
		"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
		"kKe5nrXyHOORz+ttXkYkp5uEBhpZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
		"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
		"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
		"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
		"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
		"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
		"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
		"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
		"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
		"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
		"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
		"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
		"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
		"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
		"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
		"kKe5nrXyHOORz+ttXkYkp5uEBhpZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://login.run.pivotal.io/saml/idp/SSO/alias/login.run.pivotal.io\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://login.run.pivotal.io/saml/idp/SSO/alias/login.run.pivotal.io\"/></md:IDPSSODescriptor></md:EntityDescriptor>";

	private static String METADATA_TRUST_CHECK_KEY = "MIIDaDCCAlACCQDFsMECzdtetjANBgkqhkiG9w0BAQUFADB2MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
		"CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEfMB0GA1UECgwWUGl2b3RhbCBT\n" +
		"b2Z0d2FyZSwgSW5jLjEZMBcGA1UEAwwQKi5ydW4ucGl2b3RhbC5pbzAeFw0xNTA5MDIyMzIwMDla\n" +
		"Fw0xODA5MDEyMzIwMDlaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYD\n" +
		"VQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZQaXZvdGFsIFNvZnR3YXJlLCBJbmMuMRkwFwYD\n" +
		"VQQDDBAqLnJ1bi5waXZvdGFsLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyz8C\n" +
		"OS7PJbmziNx1H2tpwSuDSX5ThqasDk/7LZ9FG8s/Zu8IqGQvswoGYx3CWgSaNbVA+Oj9zo7awoao\n" +
		"CLCVfU82O3RxH/gNRJQLwBVlgVys5n9UQ2xmTRMOcCTpR5d/zW4jCBgL4q2hjntgDbQNnQKJExgt\n" +
		"CGZJOQOFzsW3iG5NPfcAj+FPseVfD96I2OG3uxFPmO2Ov/EE7Hid6lETdNkXXEB2SxIebNgr03Dj\n" +
		"l6rFXTTdBXhi9gb+EQSZfbETsOHIDYIMLj0SpJvRcbA+7M4/Vynoxlv+/kICqFjjNATfOrqz7xoU\n" +
		"/VlMn1Z3op3cW8GH3iNHvGfIO7sdy2G0gQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCq3PQDcIss\n" +
		"cIS1Dq++d1dD4vkGt+8IzYz+ijOLECyXsSm7+b4L+CVinFZ9eF99PLlvvJZ8+zA7NfM1wRpjpdKp\n" +
		"0xLTss8yBDHcZkgwvDrH8aTwUtq8gO67wY3JuWBxjTsnoAPbH8zInkHeolCUSobPxAx9XHqbAxfu\n" +
		"a8HJjDihi+cJYEb5lPSpvY5ytcPG9JAXAHQ6aalpJjkyB+eaGRYi8s5Ejr3luI3nzJEzfUj5y0fc\n" +
		"FTv9CtDt9VfblSuHdRw4uFwat5e1Fb7LtEjATi4cKaG1+zZ80QyuChfC08for83TeQgjq7TA10FA\n" +
		"kKe5nrXyHOORz+ttXkYkp5uEBhpZ";
}
