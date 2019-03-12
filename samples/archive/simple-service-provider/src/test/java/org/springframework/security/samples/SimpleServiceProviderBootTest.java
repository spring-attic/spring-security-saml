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

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.helper.SamlTestObjectHelper;
import org.springframework.security.saml.saml2.key.KeyType;
import org.springframework.security.saml.saml2.key.SimpleKey;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.configuration.HostedServiceProviderConfiguration;
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
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.security.saml.serviceprovider.spi.DefaultSamlAuthentication;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sample.config.SamlPropertyConfiguration;

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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
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

	@MockBean
	private SamlMetadataCache cache;

	private String idpEntityId;

	@Autowired
	private SamlPropertyConfiguration config;

	private MockHttpServletRequest defaultRequest;
	private SamlTestObjectHelper helper;


	@BeforeEach
	void setUp() {
		idpEntityId = "http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		helper = new SamlTestObjectHelper(samlTime);

		given(
			cache.getMetadata(
				eq(idpEntityId),
				anyBoolean()
			)
		).willReturn(IDP_METADATA_SIMPLE.getBytes());

		given(
			cache.getMetadata(
				eq("http://localhost:8081/sample-idp/saml/idp/metadata"),
				anyBoolean()
			)
		).willReturn(IDP_METADATA_SPRING_LOCAL.getBytes());

		given(
			cache.getMetadata(
				eq("http://dual.sp-idp.com/saml/idp/metadata"),
				anyBoolean()
			)
		).willReturn(IDP_DUAL_METADATA.getBytes());
	}

	@AfterEach
	public void reset() {
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
		HostedServiceProviderConfiguration sp = config.toSamlServerConfiguration().getServiceProvider();
		assertNotNull(sp);
		assertThat(sp.getEntityId(), equalTo("spring.security.saml.sp.id"));
		assertTrue(sp.isSignMetadata());
		assertTrue(sp.isSignRequests());
		SimpleKey activeKey = sp.getKeys().get(0);
		assertNotNull(activeKey);
		List<SimpleKey> standByKeys = sp.getKeys().subList(1, sp.getKeys().size());
		assertNotNull(standByKeys);
		assertThat(standByKeys.size(), equalTo(3)); //adding encryption key
	}

	@Test
	public void testServiceProviderMetadata() throws Exception {
		ServiceProviderMetadata spm = getServiceProviderMetadata();
		assertThat(spm.getServiceProvider().getSingleLogoutService().isEmpty(), equalTo(false));
		//this gets created automatically when deserializing
		assertThat(spm.getEntityAlias(), equalTo("spring.security.saml.sp.id"));
		for (Endpoint ep : spm.getServiceProvider().getAssertionConsumerService()) {
			assertThat(ep.getLocation(), equalTo("http://localhost:8080/sample-sp/saml/sp/SSO/alias/boot-sample-sp"));
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
	public void parseDualRemoteMetadata() throws Exception {
		mockMvc.perform(
			get("/saml/sp/select")
				.accept(MediaType.TEXT_HTML)
		)
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<h1>Select an Identity Provider</h1>")))
			.andExpect(content().string(containsString("Dual IDP/SP Metadata")))
			.andReturn();
	}

	@Test
	public void authnRequest() throws Exception {
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		assertNotNull(authn);
	}

	@Test
	public void processResponse() throws Exception {
		ServiceProviderService provider = provisioning.getHostedProvider();
		String idpEntityId = "spring.security.saml.idp.id";
		AuthenticationRequest authn = getAuthenticationRequest(
			idpEntityId
		);
		IdentityProviderMetadata idp = provider.getRemoteProvider(idpEntityId);
		ServiceProviderMetadata sp = provider.getMetadata();

		Assertion assertion = helper.assertion(sp, idp, authn, "test-user@test.com", NameId.PERSISTENT);
		assertion.setSigningKey(IDP_KEY, AlgorithmMethod.RSA_SHA256, DigestMethod.SHA256);
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
		ServiceProviderService provider = provisioning.getHostedProvider();
		String idpEntityId = "http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
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
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
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

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		String redirect = mockMvc.perform(
			get(location)
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
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
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

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		String redirect = mockMvc.perform(
			get(location)
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
		AuthenticationRequest authn = getAuthenticationRequest(
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
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

		String location = sp.getServiceProvider().getSingleLogoutService().get(0).getLocation();
		location = location.substring(location.indexOf("/saml/sp"));
		String redirect = mockMvc.perform(
			get(location)
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

	protected AuthenticationRequest getAuthenticationRequest(String idpEntityId) throws Exception {
		String redirect = mockMvc.perform(
			get("/saml/sp/authenticate/alias/" + config.getServiceProvider().getAlias())
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

	private static String IDP_METADATA_SIMPLE =
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

	private static String IDP_METADATA_SPRING_LOCAL = "" +
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<md:EntityDescriptor ID=\"15b057e6-e5a8-436a-899f-5503a07ad28c\" entityID=\"spring.security.saml.idp.id\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
		"<ds:SignedInfo>\n" +
		"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
		"<ds:Reference URI=\"#15b057e6-e5a8-436a-899f-5503a07ad28c\">\n" +
		"<ds:Transforms>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
		"<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
		"</ds:Transforms>\n" +
		"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
		"<ds:DigestValue>unLQQ9S7/MhmwiBNOUlaIEDc3B2QJn5GFWPB7yCJXWQ=</ds:DigestValue>\n" +
		"</ds:Reference>\n" +
		"</ds:SignedInfo>\n" +
		"<ds:SignatureValue>\n" +
		"u97jdtMjpWN6Djiw5lTdZlCLyV7e7m12k5kskRsdCuN5ZJ2m06G08AvU+BTUkD7cEr5+ymO0VCD2\n" +
		"vqGEUE/KYi6A0xIWFCVRCVJ4UBXOImrGAdfZ5nrbDN+J9uC8nGrCVVsyEgg2ide+PJ2EJ5ywU907\n" +
		"0diQlpdsrcywDje0HDU=\n" +
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
		"utCq3RskTkHVZnbT5Xa6ITEZxSncow==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor ID=\"14f2f0e6-f1eb-4d32-a5d9-7b71f3db0747\" WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIChTCCAe4CCQDo0wjPUK8sMDANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCVVMxEzARBgNV\n" +
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
		"utCq3RskTkHVZnbT5Xa6ITEZxSncow==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIChTCCAe4CCQDo0wjPUK8sMDANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCVVMxEzARBgNV\n" +
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

	private static SimpleKey IDP_KEY = new SimpleKey(
		"test",
		"-----BEGIN RSA PRIVATE KEY-----\n" +
			"Proc-Type: 4,ENCRYPTED\n" +
			"DEK-Info: DES-EDE3-CBC,DD358F733FD89EA1\n" +
			"\n" +
			"e/vEctkYs/saPsrQ57djWbW9YZRQFVVAYH9i9yX9DjxmDuAZGjGVxwS4GkdYqiUs\n" +
			"f3jdeT96HJPKBVwj88dYaFFO8g4L6CP+ZRN3uiKXGvb606ONp1BtJBvN0b94xGaQ\n" +
			"K9q2MlqZgCLAXJZJ7Z5k7aQ2NWE7u+1GZchQSVo308ynsIptxpgqlpMZsh9oS21m\n" +
			"V5SKs03mNyk2h+VdJtch8nWwfIHYcHn9c0pDphbaN3eosnvtWxPfSLjo274R+zhw\n" +
			"RA3KNp2bdyfidluTXj40GOYObjfcm1g3sSMgZZqpY3EQUc8DEokfXQZghfBvoEe/\n" +
			"GB0k/+StrFNl0qAdOrA6PBndlySp6STwQVAsKsKlJneRO3nAHMlZ7kenHgPunACI\n" +
			"IYKIPqPKGVTm1k2FuEPDuwsneEStiThtlvQ4Nu+k6hbuplaKlZ8C2xsubzVQ3rFU\n" +
			"KNEhU65DagDH9wR9FzEXpTYUgwrr2vNRyd0TqcSxUpUx4Ra0f3gp5/kojufD8i1y\n" +
			"Fs88e8L3g1to1hCsz8yIYIiFjYNf8CuH8myDd2KjqJlyL8svKi+M2pPYl9vY1m8L\n" +
			"u4/3ZPMrGUvtAKixBZNzj95HPX0UtmC2kPMAvdvgzaPlDeH5Ee0rzPxnHI21lmyd\n" +
			"O6Sb3tc/DM9xbCCQVN8OKy/pgv1PpHMKwEE7ELpDRoVWS8DzZ43Xfy1Rm8afADAv\n" +
			"39oj4Gs08FblaHnOSP8WOr4r9SZbF1qmlMw7QkHeaF+MJzmG3d0t2XsDzKfc510m\n" +
			"gEbiD/L3Z8czwXM5g2HciAMOEVhZQJvK62KwMyOmNqBnEThBN+apsQ==\n" +
			"-----END RSA PRIVATE KEY-----",
		"-----BEGIN CERTIFICATE-----\n" +
			"MIIChTCCAe4CCQDo0wjPUK8sMDANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC\n" +
			"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
			"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxDDAKBgNVBAsMA2lkcDEhMB8GA1UE\n" +
			"AwwYaWRwLnNwcmluZy5zZWN1cml0eS5zYW1sMB4XDTE4MDUxNDE0NTUyMVoXDTI4\n" +
			"MDUxMTE0NTUyMVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9u\n" +
			"MRIwEAYDVQQHDAlWYW5jb3V2ZXIxHTAbBgNVBAoMFFNwcmluZyBTZWN1cml0eSBT\n" +
			"QU1MMQwwCgYDVQQLDANpZHAxITAfBgNVBAMMGGlkcC5zcHJpbmcuc2VjdXJpdHku\n" +
			"c2FtbDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2EuygAucRBWtYifgEH/E\n" +
			"rVUive4dZdqo72Bze4MbkPuTKLrMCLB6IXxt1p5lu+tr0JxOiRO3KFVOO3D0l+j9\n" +
			"zOow4g+JdoMQsjSzA6HtL/D9ZjXP6iUxFCYx+qmnVl3X9ipBD/HVKOBlzIqeXTSa\n" +
			"5D17uxPQVxK64UDOI3CyY4cCAwEAATANBgkqhkiG9w0BAQsFAAOBgQAj+6b6dlA6\n" +
			"SitTfz44LdnFSW9mYaeimwPP8ZtU7/3EJCzLd5eq7N/0kYPNVclZvB45I0UMT77A\n" +
			"HWrNyScm56MTcEpSuHhJHAqRAgJKbciCTNsFI928EqiWSmu//w0ASBN3bVa8nv8/\n" +
			"rafuutCq3RskTkHVZnbT5Xa6ITEZxSncow==\n" +
			"-----END CERTIFICATE-----",
		"idppassword",
		KeyType.SIGNING
	);

	private static final String IDP_DUAL_METADATA = "<ns3:EntityDescriptor xmlns:ns3=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\"\n" +
		"                      xmlns:ns2=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ns4=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n" +
		"                      ID=\"S9a4982e5-0588-4a51-8ea9-c7bb5a62dc14\" entityID=\"Zalar_73_Test\">\n" +
		"    <ns3:IDPSSODescriptor WantAuthnRequestsSigned=\"true\"\n" +
		"                          protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
		"        <ns3:KeyDescriptor use=\"signing\">\n" +
		"            <KeyInfo>\n" +
		"                <KeyName>Zalar_73_Test</KeyName>\n" +
		"                <X509Data>\n" +
		"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
		"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
		"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
		"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
		"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
		"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
		"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
		"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
		"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
		"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
		"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
		"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
		"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
		"                </X509Data>\n" +
		"            </KeyInfo>\n" +
		"        </ns3:KeyDescriptor>\n" +
		"        <ns3:KeyDescriptor use=\"encryption\">\n" +
		"            <KeyInfo>\n" +
		"                <KeyName>Zalar_73_Test</KeyName>\n" +
		"                <X509Data>\n" +
		"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
		"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
		"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
		"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
		"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
		"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
		"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
		"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
		"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
		"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
		"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
		"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
		"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
		"                </X509Data>\n" +
		"            </KeyInfo>\n" +
		"        </ns3:KeyDescriptor>\n" +
		"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/slo\"/>\n" +
		"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/slo\"/>\n" +
		"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/slo\"/>\n" +
		"        <ns3:ManageNameIDService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/mni\"/>\n" +
		"        <ns3:ManageNameIDService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/mni\"/>\n" +
		"        <ns3:ManageNameIDService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/mni\"/>\n" +
		"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
		"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
		"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
		"        <ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/idp/sso\"/>\n" +
		"    </ns3:IDPSSODescriptor>\n" +
		"    <ns3:SPSSODescriptor AuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
		"        <ns3:KeyDescriptor use=\"signing\">\n" +
		"            <KeyInfo>\n" +
		"                <KeyName>Zalar_73_Test</KeyName>\n" +
		"                <X509Data>\n" +
		"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
		"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
		"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
		"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
		"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
		"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
		"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
		"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
		"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
		"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
		"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
		"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
		"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
		"                </X509Data>\n" +
		"            </KeyInfo>\n" +
		"        </ns3:KeyDescriptor>\n" +
		"        <ns3:KeyDescriptor use=\"encryption\">\n" +
		"            <KeyInfo>\n" +
		"                <KeyName>Zalar_73_Test</KeyName>\n" +
		"                <X509Data>\n" +
		"                    <X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
		"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
		"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
		"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
		"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
		"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
		"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
		"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
		"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
		"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
		"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
		"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
		"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B</X509Certificate>\n" +
		"                </X509Data>\n" +
		"            </KeyInfo>\n" +
		"        </ns3:KeyDescriptor>\n" +
		"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/sp/slo\"/>\n" +
		"        <ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"\n" +
		"                                 Location=\"https://testportal.zalar.com/saml2/sp/slo\"/>\n" +
		"        <ns3:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
		"                                      Location=\"https://testportal.zalar.com/saml2/sp/acs\" index=\"0\"\n" +
		"                                      isDefault=\"true\"/>\n" +
		"        <ns3:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:PAOS\"\n" +
		"                                      Location=\"https://testportal.zalar.com/saml2/sp/acs\" index=\"2\"/>\n" +
		"    </ns3:SPSSODescriptor>\n" +
		"    <ns3:Organization>\n" +
		"        <ns3:OrganizationName xml:lang=\"English\">Zalar</ns3:OrganizationName>\n" +
		"        <ns3:OrganizationDisplayName xml:lang=\"English\">Zalar</ns3:OrganizationDisplayName>\n" +
		"        <ns3:OrganizationURL>http://www.zalar.com</ns3:OrganizationURL>\n" +
		"    </ns3:Organization>\n" +
		"    <ns3:ContactPerson contactType=\"administrative\">\n" +
		"        <ns3:Company>Zalar</ns3:Company>\n" +
		"        <ns3:GivenName>Firstname</ns3:GivenName>\n" +
		"        <ns3:SurName>Lastname</ns3:SurName>\n" +
		"        <ns3:EmailAddress>firstname.lastname@zalar.com</ns3:EmailAddress>\n" +
		"    </ns3:ContactPerson>\n" +
		"</ns3:EntityDescriptor>";

}
