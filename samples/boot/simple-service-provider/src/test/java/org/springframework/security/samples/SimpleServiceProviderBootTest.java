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
package org.springframework.security.samples;

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.provider.service.config.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.saml.helper.SamlTestObjectHelper.queryParams;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SimpleServiceProviderBootTest {

	@Autowired
	Clock samlTime;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private SamlTransformer transformer;

	@Autowired
	private SamlProviderProvisioning<ServiceProviderService> provisioning;

	@Autowired
	private SamlMetadataCache cache;

	private String idpEntityId;

	private String spBaseUrl;

	@Autowired
	@Qualifier("spSamlServerConfiguration")
	private SamlServerConfiguration config;

	private MockHttpServletRequest defaultRequest;
	private SamlTestObjectHelper helper;


	@BeforeEach
	void setUp() {
		idpEntityId = "http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		spBaseUrl = "http://localhost";
		defaultRequest = new MockHttpServletRequest("GET", spBaseUrl);
		helper = new SamlTestObjectHelper(samlTime);
		if (1 / 1 == 1) {
			throw new UnsupportedOperationException();
//			config.getServiceProvider().setBasePath(spBaseUrl);
		}
	}

	@AfterEach
	public void reset() {
		if (1 / 1 == 1) {
			throw new UnsupportedOperationException();
//			config.getServiceProvider().setSingleLogoutEnabled(true);
		}
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample")
	public static class SpringBootApplicationTestConfig {
	}

	@Test
	public void checkConfig() {
		assertNotNull(config);
		assertNull(config.getIdentityProvider());
		HostedServiceProviderConfiguration sp = config.getServiceProvider();
		assertNotNull(sp);
		assertThat(sp.getEntityId(), equalTo("spring.security.saml.sp.id"));
		assertTrue(sp.isSignMetadata());
		assertTrue(sp.isSignRequests());
		SimpleKey activeKey = sp.getKeys().get(0);
		assertNotNull(activeKey);
		List<SimpleKey> standByKeys = sp.getKeys().subList(1,sp.getKeys().size());
		assertNotNull(standByKeys);
		assertThat(standByKeys.size(), equalTo(2));
	}

	@Test
	public void testServiceProviderMetadata() throws Exception {
		ServiceProviderMetadata spm = getServiceProviderMetadata();
		assertThat(spm.getServiceProvider().getSingleLogoutService().isEmpty(), equalTo(false));
		//this gets created automatically when deserializing
		assertThat(spm.getEntityAlias(), equalTo("spring.security.saml.sp.id"));
		for (Endpoint ep : spm.getServiceProvider().getAssertionConsumerService()) {
			assertThat(ep.getLocation(), equalTo("http://localhost/saml/sp/SSO/alias/boot-sample-sp"));
		}
		assertThat(
			spm.getServiceProvider().getNameIds(),
			containsInAnyOrder(NameId.UNSPECIFIED, NameId.PERSISTENT, NameId.EMAIL)
		);
		for (KeyType type : asList(KeyType.SIGNING, KeyType.ENCRYPTION)) {
			Optional<SimpleKey> first = spm.getServiceProvider().getKeys().stream()
				.filter(k -> type == k.getType())
				.findFirst();
			assertThat("Key of type:" + type, first.isPresent(), equalTo(true));
		}
	}

	@Test
	public void singleLogoutDisabledMetadata() throws Exception {
		if (1 / 1 == 1) {
			throw new UnsupportedOperationException();
		}
//		config.getServiceProvider().setSingleLogoutEnabled(false);
		ServiceProviderMetadata spm = getServiceProviderMetadata();
		assertThat(spm.getServiceProvider().getSingleLogoutService(), containsInAnyOrder());
	}


	@Test
	public void authnRequest() throws Exception {
		AuthenticationRequest authn = getAuthenticationRequest();
		assertNotNull(authn);
	}

	@Test
	public void processResponse() throws Exception {
		ServiceProviderService provider = provisioning.getHostedProvider();
		if (1 / 1 == 1) {
			throw new UnsupportedOperationException();
		}
//		config.getServiceProvider().setWantAssertionsSigned(false);
		String idpEntityId = "http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		AuthenticationRequest authn = getAuthenticationRequest();
		IdentityProviderMetadata idp = provider.getRemoteProvider(idpEntityId);
		ServiceProviderMetadata sp = provider.getMetadata();
		Assertion assertion = helper.assertion(sp, idp, authn, "test-user@test.com", NameId.PERSISTENT);
		Response response = helper.response(
			authn,
			assertion,
			sp,
			idp
		);

		String encoded = transformer.samlEncode(transformer.toXml(response), false);
		mockMvc.perform(
			post("/saml/sp/SSO/alias/boot-sample-sp")
				.param("SAMLResponse", encoded)
		)
			.andExpect(status().isFound())
			.andExpect(authenticated());
	}

	@Test
	public void invalidResponse() throws Exception {
		if (1 / 1 == 1) {
			throw new UnsupportedOperationException();
		}
//		config.getServiceProvider().setWantAssertionsSigned(false);
		ServiceProviderService provider = provisioning.getHostedProvider();
		String idpEntityId = "http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		AuthenticationRequest authn = getAuthenticationRequest();
		IdentityProviderMetadata idp = provider.getRemoteProvider(idpEntityId);
		ServiceProviderMetadata sp = provider.getMetadata();
		Assertion assertion = helper.assertion(sp, idp, authn, "test-user@test.com", NameId.PERSISTENT);
		Response response = helper.response(
			authn,
			assertion,
			sp,
			idp
		);
		response.setDestination("invalid SP");

		String encoded = transformer.samlEncode(transformer.toXml(response), false);
		mockMvc.perform(
			post("/saml/sp/SSO/alias/boot-sample-sp")
				.param("SAMLResponse", encoded)
		)
			.andExpect(status().isBadRequest())
			.andExpect(content().string(containsString("Destination mismatch: invalid SP")));
	}

	@Test
	public void initiateLogout() throws Exception {
		ServiceProviderService provider = provisioning.getHostedProvider();
		AuthenticationRequest authn = getAuthenticationRequest();
		IdentityProviderMetadata idp = provider.getRemoteProvider(idpEntityId);
		ServiceProviderMetadata sp = provider.getMetadata();
		Assertion assertion = helper.assertion(sp, idp, authn, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idpEntityId,
			sp.getEntityId(),
			null
		);

		String redirect = mockMvc.perform(
			get(sp.getServiceProvider().getSingleLogoutService().get(0).getLocation())
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andReturn()
			.getResponse()
			.getHeader("Location");

		Map<String, String> params = queryParams(new URI(redirect));
		String request = params.get("SAMLRequest");
		assertNotNull(request);
		LogoutRequest lr = (LogoutRequest) transformer.fromXml(
			transformer.samlDecode(request, true),
			null,
			null
		);
		assertNotNull(lr);
	}

	@Test
	public void receiveLogoutRequest() throws Exception {
		ServiceProviderService provider = provisioning.getHostedProvider();
		AuthenticationRequest authn = getAuthenticationRequest();
		IdentityProviderMetadata idp = provider.getRemoteProvider(idpEntityId);
		ServiceProviderMetadata sp = provider.getMetadata();
		Assertion assertion = helper.assertion(sp, idp, authn, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idpEntityId,
			sp.getEntityId(),
			null
		);
		LogoutRequest request = helper.logoutRequest(
			sp,
			idp,
			assertion.getSubject().getPrincipal()
		);

		String xml = transformer.toXml(request);
		String param = transformer.samlEncode(xml, true);

		String redirect = mockMvc.perform(
			get(sp.getServiceProvider().getSingleLogoutService().get(0).getLocation())
				.param("SAMLRequest", param)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andReturn()
			.getResponse()
			.getHeader("Location");

		Map<String, String> params = queryParams(new URI(redirect));
		String response = params.get("SAMLResponse");
		assertNotNull(response);
		LogoutResponse lr = (LogoutResponse) transformer.fromXml(
			transformer.samlDecode(response, true),
			null,
			null
		);
		assertNotNull(lr);
		assertThat(lr.getStatus().getCode(), equalTo(StatusCode.SUCCESS));

	}

	@Test
	public void receiveLogoutResponse() throws Exception {
		ServiceProviderService provider = provisioning.getHostedProvider();
		AuthenticationRequest authn = getAuthenticationRequest();
		IdentityProviderMetadata idp = provider.getRemoteProvider(idpEntityId);
		ServiceProviderMetadata sp = provider.getMetadata();
		Assertion assertion = helper.assertion(sp, idp, authn, "test-user@test.com", NameId.PERSISTENT);
		DefaultSamlAuthentication authentication = new DefaultSamlAuthentication(
			true,
			assertion,
			idpEntityId,
			sp.getEntityId(),
			null
		);
		LogoutRequest request = helper.logoutRequest(
			idp,
			sp,
			assertion.getSubject().getPrincipal()
		);

		LogoutResponse response = helper.logoutResponse(request, sp, idp);

		String xml = transformer.toXml(response);
		String param = transformer.samlEncode(xml, true);

		String redirect = mockMvc.perform(
			get(sp.getServiceProvider().getSingleLogoutService().get(0).getLocation())
				.param("SAMLResponse", param)
				.with(authentication(authentication))
		)
			.andExpect(status().isFound())
			.andExpect(unauthenticated())
			.andReturn()
			.getResponse()
			.getHeader("Location");
		assertEquals(redirect, "/");
	}

	protected AuthenticationRequest getAuthenticationRequest() throws Exception {
		String idpEntityId = "http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		String redirect = mockMvc.perform(
			get("/saml/sp/discovery/alias/" + config.getServiceProvider().getAlias())
				.param("idp", idpEntityId)
		)
			.andExpect(status().isFound())
			.andReturn()
			.getResponse()
			.getHeader("Location");
		assertNotNull(redirect);
		Map<String, String> params = queryParams(new URI(redirect));
		assertNotNull(params);
		assertFalse(params.isEmpty());
		String request = params.get("SAMLRequest");
		assertNotNull(request);
		String xml = transformer.samlDecode(request, true);
		return (AuthenticationRequest) transformer.fromXml(xml, null, null);
	}

	@Test
	public void selectIdentityProvider() throws Exception {
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(containsString("Simple SAML PHP IDP")))
			.andReturn();
	}

	protected ServiceProviderMetadata getServiceProviderMetadata() throws Exception {
		String xml = mockMvc.perform(get("/saml/sp/metadata"))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertNotNull(xml);
		Metadata m = (Metadata) transformer.fromXml(xml, null, null);
		assertNotNull(m);
		assertThat(m.getClass(), equalTo(ServiceProviderMetadata.class));
		return (ServiceProviderMetadata) m;
	}

	private static String IDP_METADATA_SIMPLE = "\n" +
		"<?xml version=\"1.0\"?>\n" +
		"<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php\" ID=\"pfx82c8eef2-9b5c-578f-3b57-5f95dfb59d52\"><ds:Signature>\n" +
		"  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
		"  <ds:Reference URI=\"#pfx82c8eef2-9b5c-578f-3b57-5f95dfb59d52\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>Ggf2m64yY0eZ8l9SWRhPGaFCFNo=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>sXIdvPdAIStwnxbv+cBiZU8Diw+YGA1ZOo6Wxxsx5wXu/nqXWqEcGoK+0duuGw95yajUO0lYmhSAngXw3R9Gf5RoE+x3NnbaNwPacv6BsQiftjnWJ29qLpBOZXvlZ4VPxHvuzQCS6QSiFjj6jSwNKJLlxKPhMFjPLfirAN1M5/XHEGS+LhPQLcAiR/0neIXsHlCBFrT1JksQE3e5GDOfY674xCIOF7KGR3Ia3UXaQxM8n6+UUgfrlqiGKJefUVifexnr804N/8OI4bo6pW7IwPxl/1Ruo8ABEc2dsBIrA3DzCxsXMjBe4PTaFNc2jWot1F0b7KY+VssqHadu9j6B+A==</ds:SignatureValue>\n" +
		"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
		"  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
		"    <md:KeyDescriptor use=\"signing\">\n" +
		"      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"        <ds:X509Data>\n" +
		"          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
		"        </ds:X509Data>\n" +
		"      </ds:KeyInfo>\n" +
		"    </md:KeyDescriptor>\n" +
		"    <md:KeyDescriptor use=\"encryption\">\n" +
		"      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"        <ds:X509Data>\n" +
		"          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
		"        </ds:X509Data>\n" +
		"      </ds:KeyInfo>\n" +
		"    </md:KeyDescriptor>\n" +
		"    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SingleLogoutService.php\"/>\n" +
		"    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
		"    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php\"/>\n" +
		"  </md:IDPSSODescriptor>\n" +
		"  <md:ContactPerson contactType=\"technical\">\n" +
		"    <md:GivenName>Filip</md:GivenName>\n" +
		"    <md:SurName>Hanik</md:SurName>\n" +
		"    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
		"  </md:ContactPerson>\n" +
		"</md:EntityDescriptor>\n";

	private static String IDP_METADATA_SPRING_LOCAL = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<md:EntityDescriptor ID=\"d9b18f8e-a30e-4c56-b9fb-fd7bf7aad98c\" entityID=\"spring.security.saml.idp.id\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"<ds:SignedInfo>\n" +
		"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
		"<ds:Reference URI=\"#d9b18f8e-a30e-4c56-b9fb-fd7bf7aad98c\">\n" +
		"<ds:Transforms>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"</ds:Transforms>\n" +
		"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
		"<ds:DigestValue>Od4ciAHYLojBf7E/PcPFQe6gl7Hf3wZVvg4x5CX+hgY=</ds:DigestValue>\n" +
		"</ds:Reference>\n" +
		"</ds:SignedInfo>\n" +
		"<ds:SignatureValue>\n" +
		"qda24SfvB3wI2TELzYEAGAlAvXYJl5Z1cpOyCMOy3OmXbbRKSFckJ8pyz7COEwTndebwUnLhkbd/\n" +
		"IT9Y95ECDz3hDxNfe/9ucNnwdpK2NHxYWCdqEoeJDRZ0Q/I248ysR7/AwWyDmWpZkLBk9PG/jYKG\n" +
		"9CHfhoSvwcqGL50Kols=\n" +
		"</ds:SignatureValue>\n" +
		"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIChTCCAe4CCQDo0wjPUK8sMDANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxDDAKBgNVBAsMA2lkcDEhMB8GA1UEAwwYaWRwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MB4XDTE4MDUxNDE0NTUyMVoXDTI4MDUxMTE0NTUyMVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\n" +
		"DApXYXNoaW5ndG9uMRIwEAYDVQQHDAlWYW5jb3V2ZXIxHTAbBgNVBAoMFFNwcmluZyBTZWN1cml0\n" +
		"eSBTQU1MMQwwCgYDVQQLDANpZHAxITAfBgNVBAMMGGlkcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDCB\n" +
		"nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2EuygAucRBWtYifgEH/ErVUive4dZdqo72Bze4Mb\n" +
		"kPuTKLrMCLB6IXxt1p5lu+tr0JxOiRO3KFVOO3D0l+j9zOow4g+JdoMQsjSzA6HtL/D9ZjXP6iUx\n" +
		"FCYx+qmnVl3X9ipBD/HVKOBlzIqeXTSa5D17uxPQVxK64UDOI3CyY4cCAwEAATANBgkqhkiG9w0B\n" +
		"AQsFAAOBgQAj+6b6dlA6SitTfz44LdnFSW9mYaeimwPP8ZtU7/3EJCzLd5eq7N/0kYPNVclZvB45\n" +
		"I0UMT77AHWrNyScm56MTcEpSuHhJHAqRAgJKbciCTNsFI928EqiWSmu//w0ASBN3bVa8nv8/rafu\n" +
		"utCq3RskTkHVZnbT5Xa6ITEZxSncow==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor ID=\"8f01fc8e-7ecf-49f9-bacf-406c6f8bb1db\" WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:Extensions/><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIChTCCAe4CCQDo0wjPUK8sMDANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxDDAKBgNVBAsMA2lkcDEhMB8GA1UEAwwYaWRwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MB4XDTE4MDUxNDE0NTUyMVoXDTI4MDUxMTE0NTUyMVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\n" +
		"DApXYXNoaW5ndG9uMRIwEAYDVQQHDAlWYW5jb3V2ZXIxHTAbBgNVBAoMFFNwcmluZyBTZWN1cml0\n" +
		"eSBTQU1MMQwwCgYDVQQLDANpZHAxITAfBgNVBAMMGGlkcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDCB\n" +
		"nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2EuygAucRBWtYifgEH/ErVUive4dZdqo72Bze4Mb\n" +
		"kPuTKLrMCLB6IXxt1p5lu+tr0JxOiRO3KFVOO3D0l+j9zOow4g+JdoMQsjSzA6HtL/D9ZjXP6iUx\n" +
		"FCYx+qmnVl3X9ipBD/HVKOBlzIqeXTSa5D17uxPQVxK64UDOI3CyY4cCAwEAATANBgkqhkiG9w0B\n" +
		"AQsFAAOBgQAj+6b6dlA6SitTfz44LdnFSW9mYaeimwPP8ZtU7/3EJCzLd5eq7N/0kYPNVclZvB45\n" +
		"I0UMT77AHWrNyScm56MTcEpSuHhJHAqRAgJKbciCTNsFI928EqiWSmu//w0ASBN3bVa8nv8/rafu\n" +
		"utCq3RskTkHVZnbT5Xa6ITEZxSncow==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIChTCCAe4CCQD5tBAxQuxm/jANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxDDAKBgNVBAsMA2lkcDEhMB8GA1UEAwwYaWRwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MB4XDTE4MDUxNDE0NTYzN1oXDTI4MDUxMTE0NTYzN1owgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\n" +
		"DApXYXNoaW5ndG9uMRIwEAYDVQQHDAlWYW5jb3V2ZXIxHTAbBgNVBAoMFFNwcmluZyBTZWN1cml0\n" +
		"eSBTQU1MMQwwCgYDVQQLDANpZHAxITAfBgNVBAMMGGlkcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDCB\n" +
		"nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtzPXLWQ1x/tQ5u8E/GZn2dXUrQVqLFdLFOG/EPzX\n" +
		"dHqfhjmfsRAqcsCTyuYrY2inuME9Y5xBHghtLBkZMIiAorKZPmrGeRlYfGOZmMiRaRv5KWXGZksJ\n" +
		"pPldawNUqcOirV7mzGYNzbd7IMs1C8uwXvVpJlpQZym9ySYVPrnqsxcCAwEAATANBgkqhkiG9w0B\n" +
		"AQsFAAOBgQAEouj+xkt+Xs6ZYIz+6opshxsPXgzuNcXLji0B9fVPyyC3xI/0uDuybaDm2Im0cgw4\n" +
		"knEGJu0CLcAPZJqxC5K1c2sO5/iEg3Yy9owUex+MY752MPJIoZQrp1jV2L5Sjz6+vBNPqRORGSmw\n" +
		"zTz4iOglRkEDPs6Xo0uDH/Hc5eidjQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIChTCCAe4CCQDvIphE/c3STzANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCVVMxEzARBgNV\n" +
		"BAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5nIFNlY3Vy\n" +
		"aXR5IFNBTUwxDDAKBgNVBAsMA2lkcDEhMB8GA1UEAwwYaWRwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MB4XDTE4MDUxNDE1MTkxOFoXDTI4MDUxMTE1MTkxOFowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQI\n" +
		"DApXYXNoaW5ndG9uMRIwEAYDVQQHDAlWYW5jb3V2ZXIxHTAbBgNVBAoMFFNwcmluZyBTZWN1cml0\n" +
		"eSBTQU1MMQwwCgYDVQQLDANpZHAxITAfBgNVBAMMGGlkcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDCB\n" +
		"nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqtDYYGiAxDhYBLr2nTxgPpETurWIQd/hJDRXUK42\n" +
		"YhoNMs8jXxcCNmrSagvdaD/hwn/EU7j5E20GZdZLa85adkN0gHN6e+nu+hHw3K9dlZgla9+DfRLA\n" +
		"Dh6WHD8T/DO9sRWcpdLnNZI6p7t5mld0Q0/hhQ8wW6TQDPhdXWhRGEkCAwEAATANBgkqhkiG9w0B\n" +
		"AQsFAAOBgQAtLuQjIPKFystOYNeUGngR4mk5GgYizzR3OvgDxZGNizVCbilPoM4P3T5izpd8f/dG\n" +
		"Iioq4nzrPM//DZj/ijS9WNzrLV06T7iYpYeTKveR8TYaBaJoovrlfPaCadI7L7WatrlQaMZ2Hffn\n" +
		"sgNZROW70P9KbBF/4ejcVX96drpXiA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8081/sample-idp/saml/idp/logout/alias/boot-sample-idp\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8081/sample-idp/saml/idp/SSO/alias/boot-sample-idp\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8081/sample-idp/saml/idp/SSO/alias/boot-sample-idp\"/></md:IDPSSODescriptor></md:EntityDescriptor>";
}
